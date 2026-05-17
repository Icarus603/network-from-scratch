//! Socket-level options shared between client and server.
//!
//! Pre-iter-14 the server's `apply_tcp_keepalive` lived as a
//! private helper inside `server.rs`. The client side (SOCKS5
//! dialer) had no equivalent — every outbound TCP connection
//! went on the wire without keepalive, meaning a long-idle
//! Proteus session crossing a CGNAT / corporate firewall would
//! silently die after the NAT's idle timer fired (typically
//! 2-30 min) WITHOUT the client noticing until the next user
//! action tried to send. The user-visible symptom:
//! "everything was working, then suddenly nothing loaded; I
//! refreshed and it worked again". That's the worst kind of
//! production bug — silent connectivity loss that masquerades
//! as flaky-network.
//!
//! This module hoists the keepalive helper into a shared,
//! well-tested API both binaries use. The server keeps its
//! existing per-accept call site; the client now applies the
//! same policy to every outbound `connect` (toward both α TCP
//! and the SOCKS5 inbound that arrives).
//!
//! ## Why dup the fd?
//!
//! `socket2::Socket::from(OwnedFd)` takes ownership of the fd
//! and closes it on drop. Tokio's `TcpStream` owns the original
//! fd and would double-close if we passed the raw fd directly.
//! `libc::dup` returns a fresh fd that we own independently;
//! the `socket2::Socket` wrapper closes the dup'd fd on drop
//! while tokio's fd survives untouched.
//!
//! ## Platforms
//!
//! `socket2::TcpKeepalive::with_time` and `with_interval` are
//! available on every Unix we target (macOS, Linux, BSD). On
//! macOS, `with_interval` maps to `TCP_KEEPINTVL`; on Linux,
//! both fields map to the matching `TCP_KEEP*` socket options.
//! Windows isn't a tier-1 deployment target here — the helper
//! still compiles but `with_interval` is a no-op there.

use std::time::Duration;

use tokio::net::TcpStream;

/// Apply TCP keepalive to a tokio `TcpStream`.
///
/// `interval_secs` is used for BOTH:
///   - `TCP_KEEPIDLE` (Linux) / `TCP_KEEPALIVE` (macOS) — time
///     after which the kernel starts sending keepalive probes
///     on an idle connection.
///   - `TCP_KEEPINTVL` — time between successive probes once
///     they start firing.
///
/// A reasonable production default is 30 seconds: short enough
/// that NAT bindings (typically 2 min minimum, 5 min typical)
/// stay warm, long enough that idle-but-alive sessions don't
/// flood the wire with probes.
///
/// **Why both fields use the same value**: the canonical
/// production pattern — keep the binding warm AND fast-detect
/// dead peers — is "interval == idle time". Adjusting them
/// independently is rarely needed; future operators who want
/// asymmetric tuning can call `socket2` directly. Mirroring
/// the existing server.rs::apply_tcp_keepalive contract that
/// shipped pre-iter-14, so the new shared helper is a strict
/// behavior-preserving extraction.
///
/// Returns `Ok(())` on success. Errors (e.g., fd is gone, kernel
/// refused the option) are surfaced so callers can decide
/// whether to log-and-continue or fail. Production callers
/// universally log-and-continue: keepalive is a defense-in-depth
/// optimization, not a correctness invariant.
#[allow(unsafe_code)] // tightly-scoped: dup(2) + OwnedFd wrapper only
pub fn apply_tcp_keepalive(stream: &TcpStream, interval_secs: u64) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = stream.as_raw_fd();
    // SAFETY: dup(2) returns a fresh fd that we own. We check
    // for -1 before wrapping it in OwnedFd.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: dup_fd is a freshly-owned valid fd.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup_fd) };
    let sock = socket2::Socket::from(owned);
    let cfg = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(interval_secs))
        .with_interval(Duration::from_secs(interval_secs));
    sock.set_tcp_keepalive(&cfg)
    // `sock` drops here, closing the dup'd fd. tokio's fd is
    // untouched and continues to serve I/O.
}

/// Apply `TCP_USER_TIMEOUT` (Linux/Android/Fuchsia/Cygwin
/// only — no-op on macOS, BSD, Windows). Iter-28.
///
/// `TCP_USER_TIMEOUT` (RFC 5482) caps how long the kernel
/// will keep an actively-sending socket in `ESTABLISHED`
/// when the peer's acks are absent. Default Linux behavior
/// is the retransmit deadline (~15 min). With this set, an
/// actively-sending session whose peer goes silent
/// (kernel hang, route disappeared mid-flight, mid-tunnel
/// NAT box restarted) gets terminated within
/// `timeout_secs` instead of holding the FD + per-user
/// semaphore slot + relay-pump task for ~15 minutes.
///
/// Distinct from `apply_tcp_keepalive` (iter-14):
///   * keepalive detects DEAD IDLE sessions — the peer is
///     silent and WE'RE silent; kernel sends probes on the
///     idle timer.
///   * user_timeout detects DEAD ACTIVE sessions — WE'RE
///     trying to send but the peer's acks aren't coming
///     back; kernel forcibly closes after the timeout.
///
/// Both are needed for full production-stability coverage.
/// On macOS / BSD / Windows this fn silently no-ops (returns
/// `Ok(())`) — the underlying socket option doesn't exist on
/// those platforms, but the binary still compiles + the
/// keepalive defense is in place. Production Proteus
/// deployments target Linux VPSes; macOS is only for local
/// dev where the missing user_timeout doesn't matter.
///
/// `timeout_secs` should typically equal the operator's
/// `tcp_keepalive_secs` × a small multiple (3-5×). Setting
/// it equal to the keepalive interval is too aggressive —
/// every transient packet loss would trigger a close.
/// Setting it much larger (>5×) loses the production-
/// stability win the option exists for.
pub fn apply_tcp_user_timeout_if_supported(
    stream: &TcpStream,
    timeout: Duration,
) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[allow(unsafe_code)] // tightly-scoped: dup(2) + OwnedFd wrapper only
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let fd = stream.as_raw_fd();
            // SAFETY: dup(2) returns a fresh fd that we own.
            let dup_fd = unsafe { libc::dup(fd) };
            if dup_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: dup_fd is a freshly-owned valid fd.
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup_fd) };
            let sock = socket2::Socket::from(owned);
            return sock.set_tcp_user_timeout(Some(timeout));
        }
    }
    // No-op on macOS / BSD / Windows — option doesn't exist.
    #[allow(unreachable_code)]
    {
        let _ = (stream, timeout);
        Ok(())
    }
}

/// Convenience: apply BOTH `TCP_NODELAY` AND TCP keepalive to a
/// freshly-connected outbound stream. This is the canonical
/// "I just dialed and got a TcpStream, set production socket
/// options" path. Both calls are best-effort — failures are
/// returned via the `nodelay_err` / `keepalive_err` fields of
/// the result so callers can log them but proceed.
///
/// Why this exists: client SOCKS5 dialers and server upstream
/// dialers both need the same two-call pattern (nodelay for
/// latency, keepalive for liveness through NAT). Pre-iter-14
/// they each had their own `set_nodelay(true).ok()` call AND
/// only the server's accept-loop set keepalive; outbound dials
/// (client→server, server→upstream) had no keepalive at all.
///
/// Returns a `DialSocketOpts` struct (rather than `Result<()>`)
/// because the two operations are independent — failing to set
/// nodelay shouldn't block a session that was OK with keepalive
/// applied, and vice versa. Callers typically log non-None
/// fields at WARN and proceed.
#[must_use]
pub fn apply_dial_socket_opts(stream: &TcpStream, keepalive_secs: u64) -> DialSocketOpts {
    let nodelay_err = stream.set_nodelay(true).err();
    let keepalive_err = apply_tcp_keepalive(stream, keepalive_secs).err();
    DialSocketOpts {
        nodelay_err,
        keepalive_err,
        user_timeout_err: None,
    }
}

/// Iter-28: extended variant of [`apply_dial_socket_opts`]
/// that ALSO applies `TCP_USER_TIMEOUT` (Linux-only — see
/// [`apply_tcp_user_timeout_if_supported`] for the rationale).
///
/// `user_timeout_secs` is independent of `keepalive_secs`:
/// keepalive detects DEAD IDLE sessions; user_timeout
/// detects DEAD ACTIVE sessions (peer's acks stopped
/// arriving mid-stream). A reasonable production default:
/// `user_timeout_secs = keepalive_secs * 4` (e.g. 30s
/// keepalive → 120s user_timeout). Setting them equal is
/// too aggressive; setting user_timeout >> keepalive loses
/// the iter-28 win.
///
/// Use this on long-lived production sockets (SOCKS5 →
/// VPS dial, server → upstream dial). Short-lived RPC
/// sockets (metrics-http scrape, admin endpoint) don't
/// benefit and can stick with `apply_dial_socket_opts`.
#[must_use]
pub fn apply_dial_socket_opts_with_user_timeout(
    stream: &TcpStream,
    keepalive_secs: u64,
    user_timeout_secs: u64,
) -> DialSocketOpts {
    let nodelay_err = stream.set_nodelay(true).err();
    let keepalive_err = apply_tcp_keepalive(stream, keepalive_secs).err();
    let user_timeout_err =
        apply_tcp_user_timeout_if_supported(stream, Duration::from_secs(user_timeout_secs)).err();
    DialSocketOpts {
        nodelay_err,
        keepalive_err,
        user_timeout_err,
    }
}

/// Result of [`apply_dial_socket_opts`] (and the iter-28
/// `_with_user_timeout` variant). All fields are `None` on
/// full success.
#[derive(Debug, Default)]
pub struct DialSocketOpts {
    /// Error from `TcpStream::set_nodelay`, if any. `None` =
    /// nodelay successfully applied. Production callers can
    /// log at INFO/WARN and proceed; nodelay being absent
    /// adds latency to small writes but doesn't break
    /// correctness.
    pub nodelay_err: Option<std::io::Error>,
    /// Error from [`apply_tcp_keepalive`], if any. `None` =
    /// keepalive successfully applied. Production callers can
    /// log at INFO/WARN and proceed; keepalive being absent
    /// makes silent-death-through-NAT possible but doesn't
    /// break in-active-use connections.
    pub keepalive_err: Option<std::io::Error>,
    /// Iter-28: error from [`apply_tcp_user_timeout_if_supported`],
    /// if any. `None` = either the timeout was set OR the
    /// platform doesn't support `TCP_USER_TIMEOUT` (macOS, BSD,
    /// Windows). On Linux this is the production hardening that
    /// caps how long an actively-sending socket waits for peer
    /// acks before forcibly closing. `Some(e)` means the setsockopt
    /// failed on a platform that supports the option — log + proceed.
    pub user_timeout_err: Option<std::io::Error>,
}

impl DialSocketOpts {
    /// True iff all three options applied successfully (or
    /// the platform didn't support an option and silently
    /// no-oped it — that case returns `None` in the
    /// corresponding field, indistinguishable from "applied
    /// successfully").
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.nodelay_err.is_none()
            && self.keepalive_err.is_none()
            && self.user_timeout_err.is_none()
    }
}

/// Classify a raw OS error from `TcpListener::accept()` into
/// "transient (back off and retry)" vs "fatal (let the
/// supervisor restart us)".
///
/// Pre-iter-18 the server's accept loops propagated EVERY
/// io::Error and died on transient FD exhaustion. Iter-18
/// (server-side) fixed that with this classifier; iter-19
/// (client-side) reuses the same classifier on the client's
/// SOCKS5 accept loop so EBADF (listener dead — operator
/// renamed the socks_listen address out from under us, etc.)
/// stops the loop instead of spin-looping forever in a
/// "transient" backoff.
///
/// Transient set (back off, retry):
///   * EMFILE (24) — per-process FD limit hit
///   * ENFILE (23) — system-wide FD limit hit
///   * ENOMEM (12) — kernel out of memory for the socket
///
/// Everything else (the listener fd itself going bad,
/// kernel state-loss, network stack issues) is fatal — the
/// operator's systemd / supervisor restarts the binary.
///
/// `None` (io::Error with no raw_os_error) is treated as
/// fatal: it's not a kernel-level transient, it's an
/// internal libstd error path we shouldn't try to retry.
///
/// EAGAIN / EWOULDBLOCK (11) and EINTR (4) are NOT in the
/// transient set — tokio's `accept().await` already retries
/// on those internally; if they bubble up to our layer
/// something else is wrong and double-retrying would
/// re-introduce the spin-loop bug we just closed.
#[must_use]
pub fn is_transient_accept_error(raw_os_error: Option<i32>) -> bool {
    matches!(raw_os_error, Some(24) | Some(23) | Some(12))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// `apply_tcp_keepalive` MUST succeed on a freshly-connected
    /// loopback socket. If this regresses (e.g., a refactor
    /// passes a stale fd), every outbound dial silently loses
    /// keepalive.
    #[tokio::test]
    async fn apply_tcp_keepalive_succeeds_on_loopback_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let res = apply_tcp_keepalive(&stream, 30);
        assert!(res.is_ok(), "apply_tcp_keepalive failed: {res:?}");
        let _ = accept_task.await;
    }

    /// Dup-then-drop MUST NOT close the tokio fd. After applying
    /// keepalive we must still be able to read/write on the
    /// underlying stream.
    #[tokio::test]
    async fn applying_keepalive_does_not_invalidate_the_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            s.write_all(b"WORLD").await.unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        apply_tcp_keepalive(&stream, 30).expect("keepalive");
        stream.write_all(b"HELLO").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"WORLD");
        let _ = accept_task.await;
    }

    /// `apply_dial_socket_opts` MUST set BOTH nodelay AND
    /// keepalive on a fresh connection; both failure fields
    /// should be None on success.
    #[tokio::test]
    async fn apply_dial_socket_opts_sets_both_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let opts = apply_dial_socket_opts(&stream, 30);
        assert!(
            opts.all_ok(),
            "expected both nodelay and keepalive to apply: {opts:?}"
        );
        // Explicit field check too — if one mode silently
        // returns ok with the OTHER field's error, all_ok()
        // would still pass.
        assert!(
            opts.nodelay_err.is_none(),
            "nodelay failed: {:?}",
            opts.nodelay_err
        );
        assert!(
            opts.keepalive_err.is_none(),
            "keepalive failed: {:?}",
            opts.keepalive_err
        );
        let _ = accept_task.await;
    }

    /// Keepalive at very short intervals MUST still apply.
    /// (Operator overrides — e.g. `tcp_keepalive_secs: 5` in
    /// a deployment behind aggressive NAT — must work without
    /// the helper rejecting small values.)
    #[tokio::test]
    async fn apply_tcp_keepalive_accepts_short_intervals() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        apply_tcp_keepalive(&stream, 1).expect("1s keepalive");
        let _ = accept_task.await;
    }

    // ---- iter-18/19: accept-error classifier (moved here in iter-19) ----

    /// EMFILE = errno 24 (per-process FD limit). Most common
    /// transient on a busy server.
    #[test]
    fn emfile_classified_as_transient() {
        assert!(is_transient_accept_error(Some(24)));
    }

    /// ENFILE = errno 23 (system-wide FD limit).
    #[test]
    fn enfile_classified_as_transient() {
        assert!(is_transient_accept_error(Some(23)));
    }

    /// ENOMEM = errno 12 (kernel out of memory for the socket).
    #[test]
    fn enomem_classified_as_transient() {
        assert!(is_transient_accept_error(Some(12)));
    }

    /// EBADF (errno 9, listener fd is dead) MUST kill the
    /// accept loop — systemd / the operator's supervisor
    /// should restart us. If we accidentally classified this
    /// as transient we'd spin forever logging EBADF every
    /// 5 seconds.
    #[test]
    fn ebadf_classified_as_fatal() {
        assert!(!is_transient_accept_error(Some(9)));
    }

    /// EINTR / EAGAIN are technically transient but tokio's
    /// `accept().await` already retries on those internally
    /// — they should NEVER bubble up to our layer. If they
    /// do, treat as fatal so we don't accidentally double-
    /// retry. Same logic for "no raw_os_error" — that's an
    /// io::Error from some other source (libstd-internal),
    /// not a kernel-level transient.
    #[test]
    fn eagain_and_none_classified_as_fatal() {
        assert!(!is_transient_accept_error(Some(11))); // EAGAIN/EWOULDBLOCK
        assert!(!is_transient_accept_error(Some(4))); // EINTR
        assert!(!is_transient_accept_error(None));
    }

    /// Sanity: ECONNRESET (104) is a per-CONNECTION error,
    /// not an accept-level problem. The kernel still hands us
    /// the accepted fd; the read on that fd later returns
    /// ECONNRESET. So `accept()` itself returning 104 is
    /// pathological and we kill the loop.
    #[test]
    fn econnreset_classified_as_fatal() {
        assert!(!is_transient_accept_error(Some(104)));
    }

    // ---- iter-28: TCP_USER_TIMEOUT tests ----

    /// `apply_tcp_user_timeout_if_supported` MUST return Ok
    /// on every supported platform — and silently no-op on
    /// macOS/BSD/Windows. This test runs on the developer's
    /// macOS and asserts the no-op path; on Linux CI it
    /// would exercise the real setsockopt path. Both paths
    /// must return Ok for a fresh loopback socket.
    #[tokio::test]
    async fn apply_tcp_user_timeout_succeeds_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let r = apply_tcp_user_timeout_if_supported(&stream, Duration::from_secs(120));
        assert!(
            r.is_ok(),
            "apply_tcp_user_timeout_if_supported should Ok (or no-op) on loopback, got {r:?}"
        );
        let _ = accept_task.await;
    }

    /// `apply_dial_socket_opts_with_user_timeout` applies all
    /// three options. On macOS the user_timeout no-ops
    /// (returns Ok internally → field stays None), so
    /// `all_ok()` is true. On Linux all three setsockopts
    /// fire successfully.
    #[tokio::test]
    async fn apply_dial_socket_opts_with_user_timeout_all_three_options() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let opts = apply_dial_socket_opts_with_user_timeout(&stream, 30, 120);
        assert!(
            opts.all_ok(),
            "iter-28: all_ok must be true on loopback, got {opts:?}"
        );
        let _ = accept_task.await;
    }

    /// Iter-28 invariant: the legacy
    /// `apply_dial_socket_opts` (no user_timeout) MUST still
    /// produce `user_timeout_err = None`. That's the back-
    /// compat contract — callers using the legacy fn name
    /// shouldn't see a spurious "user_timeout_err: Some(...)"
    /// surface.
    #[tokio::test]
    async fn legacy_apply_dial_socket_opts_leaves_user_timeout_err_unset() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let opts = apply_dial_socket_opts(&stream, 30);
        assert!(opts.user_timeout_err.is_none());
        assert!(opts.all_ok());
        let _ = accept_task.await;
    }
}
