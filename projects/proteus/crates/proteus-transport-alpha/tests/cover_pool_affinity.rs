//! End-to-end test for `ServerCtx::with_cover_pool` + per-source-IP
//! affinity routing.
//!
//! ## What this pins
//!
//! Two distinct mock cover servers (A, B) running on different
//! ports. A Proteus server with `cover_pool = [A, B]` configured.
//! An attacker that sends garbage on a loopback connection always
//! receives the same cover's sentinel across repeated probes
//! (affinity).
//!
//! Why this matters: the affinity discipline is the load-bearing
//! property of the cover pool. Without affinity, a single observer
//! probing the Proteus server across hours would see the cover URL
//! rotate — itself a fingerprint distinguishing Proteus from a real
//! cover server (which would never rotate destinations between
//! back-to-back requests). With affinity, each src IP sees one URL
//! consistently, matching the real-cover-server behavior pattern.
//!
//! The single-process limitation: every probe in this test comes
//! from `127.0.0.1` so the affinity hash collapses every probe to
//! one bucket regardless of pool size. We exercise the
//! "consistent across probes" half of the property here; the
//! "distributes across different src IPs" half is unit-tested in
//! `cover_pool::tests::multi_pool_distributes_across_different_slash24s`
//! (which can synthesize arbitrary src IPs without sockets).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Spawn a labelled cover server. Returns the bind addr + a counter
/// that increments on every accepted connection.
async fn spawn_cover_labelled(label: &'static [u8]) -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let counter_clone = Arc::clone(&counter);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            counter_clone.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nServer: cover-pool-test\r\n\r\nLABEL:{}",
                    std::str::from_utf8(label).unwrap()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, counter)
}

/// Drive one garbage probe against `proxy_addr`, return whatever
/// label the cover replied with (or None on read failure).
async fn probe_once(proxy_addr: std::net::SocketAddr) -> Option<String> {
    let mut stream = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .ok()?
        .ok()?;
    // Same auth-fail trigger as cover_forward.rs — first byte not a
    // valid frame kind.
    timeout(STEP, stream.write_all(&[0x55, 0x00]))
        .await
        .ok()?
        .ok()?;
    timeout(STEP, stream.flush()).await.ok()?.ok()?;

    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(b"LABEL:".len()).any(|w| w == b"LABEL:") {
            break;
        }
    }
    // Extract the label suffix.
    let body = String::from_utf8_lossy(&response);
    body.find("LABEL:")
        .map(|idx| body[idx + 6..].chars().take(1).collect::<String>())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cover_pool_routes_consistently_for_loopback_src_across_many_probes() {
    // Two distinct cover servers — labels "A" and "B".
    let (cover_a, count_a) = spawn_cover_labelled(b"A").await;
    let (cover_b, count_b) = spawn_cover_labelled(b"B").await;

    // Proteus server with a 2-entry cover pool.
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys).with_cover_pool(vec![cover_a.to_string(), cover_b.to_string()]),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {
        // No legitimate sessions expected.
    }));

    // Drive 8 probes from this loopback src (the OS assigns a fresh
    // ephemeral source port each time, but the IP is constant at
    // 127.0.0.1 — affinity hashes on the /24, so they MUST all
    // collapse to the same cover server).
    let mut labels = Vec::new();
    for _ in 0..8 {
        if let Some(label) = probe_once(proxy_addr).await {
            labels.push(label);
        }
    }

    assert!(
        labels.len() >= 6,
        "expected ≥6 successful probes; got {} ({:?})",
        labels.len(),
        labels,
    );

    let first = &labels[0];
    for (i, label) in labels.iter().enumerate() {
        assert_eq!(
            label, first,
            "probe {i} hit cover {label:?} but probe 0 hit {first:?} — affinity rotation regression"
        );
    }

    // Whichever bucket loopback hashed into MUST have received all
    // probes; the other MUST have received zero. That's the precise
    // statement of "no rotation".
    let a = count_a.load(Ordering::Relaxed);
    let b = count_b.load(Ordering::Relaxed);
    assert!(
        (a == 0 && b > 0) || (b == 0 && a > 0),
        "expected one cover to be fully selected and the other to be \
         untouched; got A={a}, B={b}",
    );

    server_task.abort();
}

/// Pool of size 1 must behave EXACTLY like the pre-pool single-cover
/// configuration: every probe routes to the only entry, no panic, no
/// "pool has zero entries" misbehavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cover_pool_of_size_one_routes_every_probe_to_the_sole_entry() {
    let (cover_a, count_a) = spawn_cover_labelled(b"S").await;

    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys).with_cover_pool(vec![cover_a.to_string()]));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    for _ in 0..4 {
        let label = probe_once(proxy_addr).await;
        assert_eq!(label.as_deref(), Some("S"));
    }
    assert!(count_a.load(Ordering::Relaxed) >= 4);

    server_task.abort();
}

/// Empty pool is rejected at construction — operator likely meant
/// to add entries; we don't want silent "cover disabled" surprises.
/// `with_cover_pool(Vec::new())` returns the ServerCtx unchanged
/// (cover stays None), so an empty-pool deploy behaves identically
/// to a no-cover deploy.
#[tokio::test]
async fn empty_pool_leaves_cover_unset() {
    let server_keys = ServerKeys::generate();
    let ctx = ServerCtx::new(server_keys).with_cover_pool(Vec::new());
    assert!(ctx.cover_pool().is_none());
    assert!(ctx
        .cover_endpoint_for(&"127.0.0.1:1".parse().unwrap())
        .is_none());
}

/// Backward-compat: `with_cover` (the pre-pool single-URL setter)
/// must still work AND must surface through both the legacy
/// `cover_endpoint()` accessor and the new `cover_endpoint_for()`
/// affinity accessor.
#[tokio::test]
async fn with_cover_legacy_setter_still_works() {
    let server_keys = ServerKeys::generate();
    let ctx = ServerCtx::new(server_keys).with_cover("www.example.com:443");
    assert_eq!(ctx.cover_endpoint().as_deref(), Some("www.example.com:443"),);
    assert_eq!(
        ctx.cover_endpoint_for(&"203.0.113.7:12345".parse().unwrap())
            .as_deref(),
        Some("www.example.com:443"),
    );
    // Pool size = 1.
    assert_eq!(ctx.cover_pool().map(|p| p.len()), Some(1));
}
