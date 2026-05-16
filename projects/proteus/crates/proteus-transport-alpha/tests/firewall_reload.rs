//! SIGHUP-style firewall hot-reload integration test.
//!
//! Mirrors the cert hot-reload test (tls_reload.rs) for the CIDR
//! firewall. Scenario:
//!
//! 1. Stand up a server with an empty firewall + cover server.
//! 2. Connect from loopback, observe handshake-failure → cover-route
//!    (NOT firewall-deny) — baseline that the cover path works
//!    without a firewall rule in play.
//! 3. Operator hot-reloads the firewall to deny 127.0.0.0/8.
//! 4. Connect again. The connection MUST still be routed to cover
//!    (REALITY indistinguishability) AND `firewall_denied_total`
//!    must increment (proving the new rule is in force).
//!
//! Also: any in-flight session opened BEFORE the reload is
//! unaffected by it, but the firewall is evaluated at accept(), not
//! per-record — so we only need to verify new connections see the
//! new policy.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::firewall::{Firewall, ReloadableFirewall};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const SENTINEL: &[u8] = b"HTTP/1.1 200 OK\r\nServer: cover\r\n\r\nHELLO";
const STEP: Duration = Duration::from_secs(10);

async fn spawn_cover() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
                let _ = stream.write_all(SENTINEL).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

async fn probe_to_cover(proxy_addr: std::net::SocketAddr) -> bool {
    let mut sock = match timeout(STEP, TcpStream::connect(proxy_addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    // Send a parseable-but-wrong frame so the handshake commits to
    // the decoder, sees `kind != FRAME_CLIENT_HELLO`, and routes to
    // cover. Same trigger as the cover_forward integration test.
    let _ = sock.write_all(&[0x55, 0x00]).await;
    let _ = sock.flush().await;
    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_style_firewall_reload_takes_effect_on_next_accept() {
    let cover_addr = spawn_cover().await;

    let server_keys = ServerKeys::generate();
    let metrics = Arc::new(ServerMetrics::default());

    // Start with an empty firewall.
    let firewall = ReloadableFirewall::default();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_reloadable_firewall(firewall.clone())
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // ----- Phase 1: empty firewall, garbage handshake routes to
    //       cover via the auth-fail path, firewall_denied stays 0. -----
    let ok = probe_to_cover(proxy_addr).await;
    assert!(ok, "baseline cover-forward (auth-fail path) must work");
    let denied_phase1 = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        denied_phase1, 0,
        "firewall_denied must NOT increment in phase 1 (no rules yet)"
    );

    // ----- Phase 2: install a deny rule. The next probe MUST be
    //       firewall-denied (and still routed to cover). -----
    let mut fw = Firewall::new();
    fw.extend_deny(["127.0.0.0/8"]).unwrap();
    firewall.reload(fw);
    assert!(
        firewall.is_active(),
        "firewall should be active post-reload"
    );

    let ok2 = probe_to_cover(proxy_addr).await;
    assert!(ok2, "denied connection must still reach cover server");
    let denied_phase2 = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        denied_phase2 >= 1,
        "firewall_denied must increment after reload; got {denied_phase2}"
    );

    // ----- Phase 3: clear the rules. Next probe should NOT trigger
    //       firewall_denied. -----
    firewall.reload(Firewall::new());
    assert!(
        !firewall.is_active(),
        "firewall should be inactive after clear"
    );

    let before = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    let _ = probe_to_cover(proxy_addr).await;
    let after = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        before, after,
        "firewall_denied must NOT increment after clearing rules"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloadable_firewall_concurrent_reloads_dont_panic() {
    // Stress: hammer .reload() from one thread while another spams
    // .admit(). The RwLock must not deadlock or panic.
    let fw = ReloadableFirewall::default();

    let writer = {
        let fw = fw.clone();
        std::thread::spawn(move || {
            for i in 0..200 {
                let mut new = Firewall::new();
                if i % 2 == 0 {
                    new.extend_deny([format!("192.0.2.{}/32", i % 256)])
                        .unwrap();
                } else {
                    new.extend_allow([format!("10.0.{}.0/24", i % 256)])
                        .unwrap();
                }
                fw.reload(new);
                std::thread::yield_now();
            }
        })
    };
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let fw = fw.clone();
            std::thread::spawn(move || {
                let ip: std::net::IpAddr = "192.0.2.42".parse().unwrap();
                for _ in 0..2000 {
                    let _ = fw.admit(ip);
                    let _ = fw.is_active();
                }
            })
        })
        .collect();

    writer.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }
}
