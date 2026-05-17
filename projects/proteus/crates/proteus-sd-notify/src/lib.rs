//! Minimal sd_notify(3) client + watchdog heartbeat for Proteus.
//!
//! ## Why this exists
//!
//! The bundled `proteus-server.service` unit is `Type=simple`,
//! which means:
//!
//!   1. **systemd has no idea WHEN the binary is actually ready
//!      to accept traffic.** With `Type=simple`, systemd marks the
//!      service "active" the moment the process is forked — long
//!      before TLS cert loading, listener bind, or the loopback
//!      self-test finishes. A reverse-proxy ordered with
//!      `After=proteus-server.service` can race-start while the
//!      backend is still loading and serve a wave of 502s.
//!   2. **systemd has no LIVENESS signal beyond "the process
//!      hasn't exited".** A deadlocked tokio runtime — say a
//!      lock contention bug that wedges every worker thread —
//!      keeps the process alive, so systemd never restarts it.
//!      The accept loop is dead, every connection times out at
//!      the client side, but `systemctl status` says "active
//!      (running)" forever.
//!
//! This crate implements the two missing pieces:
//!
//!   * `notify_ready()` — sends `READY=1` to systemd's notify
//!     socket once the listener is actually bound and the self-
//!     test has passed. Operator changes the unit to
//!     `Type=notify` and downstream services ordered `After=` see
//!     "active" only when Proteus genuinely is.
//!   * `spawn_watchdog(interval)` — periodically pings
//!     `WATCHDOG=1`. The unit declares `WatchdogSec=N` and
//!     systemd restarts the process if no ping arrives within
//!     `N` seconds. A deadlocked runtime fails to schedule the
//!     ping task → systemd notices → restart. Loss-tolerant
//!     restart cap on a real liveness signal.
//!   * `notify_stopping()` — sends `STOPPING=1` on graceful
//!     shutdown. Tells systemd "I'm draining, give me the full
//!     `TimeoutStopSec` window" instead of killing us at
//!     `Restart=on-failure` defaults.
//!
//! ## Why a custom crate (no `libsystemd` / `sd-notify`)
//!
//! The systemd notify protocol is one paragraph (see
//! `sd_notify(3)`): connect to the unix-domain datagram socket
//! at `$NOTIFY_SOCKET`, send a `key=value\n` payload, done. No
//! handshake, no version negotiation, no FFI required. The
//! existing Rust crates (`sd-notify`, `libsystemd`) either pull
//! in `libsystemd.so` as a dynamic dep (breaks on alpine/musl
//! containers) or are wrappers around the same datagram we send
//! ourselves. Implementing the protocol natively means:
//!
//!   * **Zero external deps** — just `tokio::net::UnixDatagram`.
//!   * **Container-friendly** — works on any glibc / musl / alpine
//!     image where systemd is present; gracefully no-ops when
//!     `$NOTIFY_SOCKET` is unset (i.e. the binary launched
//!     manually, not via systemd).
//!   * **`unsafe_code = "forbid"`** — no FFI.
//!
//! ## What this is NOT
//!
//! - Not a full sd_notify wrapper — we ship `READY=1`,
//!   `WATCHDOG=1`, `STOPPING=1`, `STATUS=`, and `RELOADING=1`.
//!   `MAINPID=`, `FDSTORE=`, etc. aren't needed for the Proteus
//!   use case.
//! - Not a substitute for `proteus_panics_total` or
//!   `proteus_restarts_total` — those track WHAT went wrong;
//!   sd_notify tells systemd WHEN to act. The two layers
//!   complement each other.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixDatagram;

/// Outcome of [`notify_ready`] / [`notify_stopping`] / etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyResult {
    /// The message was sent to systemd successfully.
    Sent,
    /// `$NOTIFY_SOCKET` is unset — running outside systemd, or
    /// under `Type=simple` where systemd didn't export it. Both
    /// are common and benign; we don't fail the binary on this.
    NotConfigured,
    /// `$NOTIFY_SOCKET` is set but the datagram send failed
    /// (permission, broken socket, kernel resource exhaustion).
    /// Operator log line is enough — we don't crash the server
    /// because systemd-notify is observability, not safety.
    SendFailed(String),
}

/// Send `READY=1` to systemd's notify socket. Call once AFTER the
/// listener is bound and the startup self-test has passed.
///
/// Idempotent — sending twice is harmless; systemd ignores the
/// second one. Async because the underlying socket is async, but
/// the actual send is sub-millisecond on a healthy kernel.
pub async fn notify_ready() -> NotifyResult {
    notify_raw("READY=1\n").await
}

/// Send `STOPPING=1` on graceful shutdown. Tells systemd we're
/// draining; combine with `TimeoutStopSec=` in the unit file so
/// systemd waits the full drain window before SIGKILL.
pub async fn notify_stopping() -> NotifyResult {
    notify_raw("STOPPING=1\n").await
}

/// Send `RELOADING=1` when the operator triggers a SIGHUP-driven
/// hot reload. Optional but useful — `systemctl status` shows
/// "reloading" instead of "active (running)" during the reload
/// window.
pub async fn notify_reloading() -> NotifyResult {
    notify_raw("RELOADING=1\n").await
}

/// Send a free-form `STATUS=` line that surfaces in
/// `systemctl status proteus-server` under the unit summary. Use
/// for human-readable state ("draining 3 sessions", "TLS cert
/// reloaded 12:34:56 UTC", etc.). Empty / blank inputs are
/// rejected client-side so we don't accidentally clear systemd's
/// status line.
pub async fn notify_status(status: &str) -> NotifyResult {
    let s = status.trim();
    if s.is_empty() {
        return NotifyResult::SendFailed("status payload empty".to_string());
    }
    notify_raw(&format!("STATUS={s}\n")).await
}

/// Read the `$NOTIFY_SOCKET` env var into a usable path. The
/// kernel-supplied value is either `/path/to/sock` (path-based)
/// or `@abstract-name` (Linux abstract namespace; we don't yet
/// support that — bundle as path-based at unit-file generation
/// time).
fn notify_socket_path() -> Option<PathBuf> {
    let v = env::var_os("NOTIFY_SOCKET")?;
    let s = v.to_string_lossy().to_string();
    if s.starts_with('@') {
        // Linux abstract namespace — supported by sd_notify but
        // requires Unix-platform-specific socket creation that
        // we'd need raw libc bindings for. Log and skip; ship
        // with path-based sockets in the systemd unit (the
        // default on modern systemd).
        tracing::warn!(
            target: "proteus_sd_notify",
            "$NOTIFY_SOCKET points at an abstract-namespace address ({}); \
             only path-based sockets are supported. Set the unit to use a \
             concrete path (NotifyAccess=all or omit the abstract prefix).",
            s
        );
        return None;
    }
    Some(PathBuf::from(s))
}

/// Send a raw key=value line to the notify socket. All public
/// senders go through this helper.
async fn notify_raw(payload: &str) -> NotifyResult {
    let Some(path) = notify_socket_path() else {
        return NotifyResult::NotConfigured;
    };
    // Bind an autobind anonymous client socket. The notify
    // socket is connection-less SOCK_DGRAM — we just need a
    // local descriptor to send_to() from.
    let sock = match UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: "proteus_sd_notify",
                error = %e,
                "could not create unbound UnixDatagram for sd_notify; downgrade to no-op"
            );
            return NotifyResult::SendFailed(e.to_string());
        }
    };
    match sock.send_to(payload.as_bytes(), &path).await {
        Ok(_) => {
            tracing::debug!(
                target: "proteus_sd_notify",
                payload = %payload.trim(),
                path = ?path,
                "sd_notify message sent"
            );
            NotifyResult::Sent
        }
        Err(e) => {
            tracing::warn!(
                target: "proteus_sd_notify",
                error = %e,
                path = ?path,
                payload = %payload.trim(),
                "sd_notify send failed"
            );
            NotifyResult::SendFailed(e.to_string())
        }
    }
}

/// Determine the watchdog interval from `$WATCHDOG_USEC` (set by
/// systemd when the unit declares `WatchdogSec=N`). Returns the
/// recommended PING interval — half the systemd-supplied timeout
/// so transient send failures + clock skew don't trigger a false
/// "watchdog tripped" restart.
///
/// Returns `None` when the env var is unset (no watchdog in
/// effect) or unparseable.
#[must_use]
pub fn watchdog_interval() -> Option<Duration> {
    let raw = env::var("WATCHDOG_USEC").ok()?;
    let usec: u64 = raw.parse().ok()?;
    if usec == 0 {
        return None;
    }
    // sd_notify(3) explicitly recommends pinging at half the
    // configured timeout to absorb scheduling jitter + network
    // round-trips.
    Some(Duration::from_micros(usec / 2))
}

/// Spawn a background tokio task that pings `WATCHDOG=1` at the
/// supplied interval. Returns a `WatchdogHandle` whose `abort()`
/// kills the task cleanly on graceful shutdown.
///
/// Designed to be called once from `main()` AFTER `notify_ready`.
/// The task takes a `cancel: Arc<tokio::sync::Notify>` and exits
/// cleanly when notified — operators don't need to abort() the
/// handle in the success path, but doing so on shutdown stops
/// the ping cycle so systemd doesn't see a stale `WATCHDOG=1`
/// during the drain window.
pub fn spawn_watchdog(interval: Duration, cancel: Arc<tokio::sync::Notify>) -> WatchdogHandle {
    let task = tokio::spawn(async move {
        // First ping happens AT the interval, not at t=0 — we
        // assume the caller has already done `notify_ready`
        // which counts as a "I'm alive" signal to systemd.
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Discard the immediate-fire first tick so we wait one
        // full interval before the first WATCHDOG ping.
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let _ = notify_raw("WATCHDOG=1\n").await;
                }
                () = cancel.notified() => {
                    tracing::debug!(target: "proteus_sd_notify", "watchdog task cancelled");
                    return;
                }
            }
        }
    });
    WatchdogHandle { task }
}

/// Handle to the watchdog ping task. Hold for the lifetime of the
/// process; `abort()` on graceful shutdown to stop pinging
/// systemd (so it can do its TimeoutStopSec accounting cleanly).
#[derive(Debug)]
pub struct WatchdogHandle {
    task: tokio::task::JoinHandle<()>,
}

impl WatchdogHandle {
    /// Cancel the watchdog task. Idempotent. Use the `Notify`
    /// path supplied to `spawn_watchdog` for clean shutdown;
    /// this is the panic/emergency stop.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Is the task still alive (or has it been aborted /
    /// completed)? Useful for tests.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::UnixDatagram;

    /// Lock used by every test that mutates the NOTIFY_SOCKET env var.
    /// `cargo test` runs tests in the same process — without this
    /// lock, parallel tests would race on env::set_var/remove_var
    /// and one test would see another's socket path. The lock IS
    /// held across an await in some tests (so the env-var mutation,
    /// send, and recv happen atomically); module-level
    /// `await_holding_lock` allow covers it — tests are
    /// single-threaded-per-test by virtue of this serialization, no
    /// risk of the std-Mutex pinning the runtime.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn unique_socket_path(suffix: &str) -> std::path::PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let p = std::path::PathBuf::from(format!(
            "{base}/proteus-sd-notify-{suffix}-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Bind a UnixDatagram listener and receive ONE datagram, with
    /// a tight timeout so a missing message fails the test fast.
    async fn receive_one(sock: &UnixDatagram) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => buf[..n].to_vec(),
            Ok(Err(e)) => panic!("recv failed: {e}"),
            Err(_) => panic!("timed out waiting for sd_notify message"),
        }
    }

    #[tokio::test]
    async fn notify_ready_sends_ready_eq_one_to_configured_socket() {
        let _g = ENV_LOCK.lock().unwrap();
        let path = unique_socket_path("ready");
        let listener = UnixDatagram::bind(&path).unwrap();
        // SAFETY for set_var: we hold ENV_LOCK so no other test
        // mutates concurrently. This is safe in single-threaded
        // env-mutation contexts.
        // Compiler disallows env::set_var without unsafe on
        // edition 2024, but this crate is edition 2021 + tests
        // gate via ENV_LOCK above.
        std::env::set_var("NOTIFY_SOCKET", &path);

        let result = notify_ready().await;
        let msg = receive_one(&listener).await;

        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result, NotifyResult::Sent);
        assert_eq!(msg, b"READY=1\n");
    }

    #[tokio::test]
    async fn notify_ready_is_no_op_when_env_var_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("NOTIFY_SOCKET");
        let result = notify_ready().await;
        assert_eq!(result, NotifyResult::NotConfigured);
    }

    #[tokio::test]
    async fn notify_stopping_sends_stopping_eq_one() {
        let _g = ENV_LOCK.lock().unwrap();
        let path = unique_socket_path("stopping");
        let listener = UnixDatagram::bind(&path).unwrap();
        std::env::set_var("NOTIFY_SOCKET", &path);

        let result = notify_stopping().await;
        let msg = receive_one(&listener).await;

        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result, NotifyResult::Sent);
        assert_eq!(msg, b"STOPPING=1\n");
    }

    #[tokio::test]
    async fn notify_status_rejects_empty_payload() {
        let _g = ENV_LOCK.lock().unwrap();
        // No socket needed — the empty-payload check fires before
        // any send attempt.
        let result = notify_status("   ").await;
        assert!(matches!(result, NotifyResult::SendFailed(_)));
    }

    #[tokio::test]
    async fn notify_status_sends_status_eq_message() {
        let _g = ENV_LOCK.lock().unwrap();
        let path = unique_socket_path("status");
        let listener = UnixDatagram::bind(&path).unwrap();
        std::env::set_var("NOTIFY_SOCKET", &path);

        let result = notify_status("draining 3 sessions").await;
        let msg = receive_one(&listener).await;

        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(&path);

        assert_eq!(result, NotifyResult::Sent);
        assert_eq!(msg, b"STATUS=draining 3 sessions\n");
    }

    #[tokio::test]
    async fn abstract_namespace_socket_is_treated_as_not_configured() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("NOTIFY_SOCKET", "@some-abstract-socket-name");
        let result = notify_ready().await;
        std::env::remove_var("NOTIFY_SOCKET");
        assert_eq!(result, NotifyResult::NotConfigured);
    }

    #[test]
    fn watchdog_interval_returns_half_of_watchdog_usec() {
        let _g = ENV_LOCK.lock().unwrap();
        // 10 seconds in microseconds — half = 5 seconds.
        std::env::set_var("WATCHDOG_USEC", "10000000");
        let d = watchdog_interval().expect("should parse");
        std::env::remove_var("WATCHDOG_USEC");
        assert_eq!(d, Duration::from_micros(5_000_000));
    }

    #[test]
    fn watchdog_interval_returns_none_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WATCHDOG_USEC");
        assert!(watchdog_interval().is_none());
    }

    #[test]
    fn watchdog_interval_returns_none_for_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WATCHDOG_USEC", "0");
        let r = watchdog_interval();
        std::env::remove_var("WATCHDOG_USEC");
        assert!(r.is_none());
    }

    #[test]
    fn watchdog_interval_returns_none_for_garbage_input() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WATCHDOG_USEC", "not-a-number");
        let r = watchdog_interval();
        std::env::remove_var("WATCHDOG_USEC");
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn spawn_watchdog_pings_at_configured_interval() {
        let _g = ENV_LOCK.lock().unwrap();
        let path = unique_socket_path("wd-pings");
        let listener = UnixDatagram::bind(&path).unwrap();
        std::env::set_var("NOTIFY_SOCKET", &path);

        let cancel = Arc::new(tokio::sync::Notify::new());
        let handle = spawn_watchdog(Duration::from_millis(50), Arc::clone(&cancel));

        // Receive at least 2 pings — confirms the interval task
        // is making forward progress.
        let m1 = receive_one(&listener).await;
        let m2 = receive_one(&listener).await;

        cancel.notify_one();
        // Give the task a chance to exit cleanly.
        tokio::time::sleep(Duration::from_millis(20)).await;

        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(&path);

        assert_eq!(m1, b"WATCHDOG=1\n");
        assert_eq!(m2, b"WATCHDOG=1\n");
        // Don't strictly require is_finished here — abort vs
        // notify race may leave it just-about-to-exit. The
        // important property is the protocol semantics.
        handle.abort();
    }

    #[tokio::test]
    async fn spawn_watchdog_exits_on_cancel_notify() {
        let _g = ENV_LOCK.lock().unwrap();
        // Use a long interval so the watchdog wouldn't naturally
        // produce a ping in the test window — only the cancel
        // notify can exit it cleanly.
        let cancel = Arc::new(tokio::sync::Notify::new());
        let handle = spawn_watchdog(Duration::from_secs(60), Arc::clone(&cancel));
        // Pre-existing socket-or-not doesn't matter; we're
        // testing exit semantics.
        cancel.notify_one();
        // Wait a small window for the task to observe the notify.
        for _ in 0..50 {
            if handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            handle.is_finished(),
            "watchdog should have exited within 500ms of cancel"
        );
    }
}
