//! Structured per-session access log (JSON Lines).
//!
//! Distinct from `tracing`'s human-friendly diagnostic stream — this
//! module emits one line of canonical JSON per completed session,
//! suitable for ingestion into Loki / CloudWatch / OpenSearch /
//! Datadog without further parsing. The format is deliberately
//! minimal so operators can downstream-extract whatever fields they
//! actually need:
//!
//! ```json
//! {"ts":"2026-05-16T12:34:56.789Z","user_id":"alice001",
//!  "peer":"203.0.113.42:54321","duration_ms":12345,
//!  "tx_bytes":1024,"rx_bytes":2048,"close_reason":"upstream_eof"}
//! ```
//!
//! Each field is independently optional from the emitter's point of
//! view (some sessions die before `user_id` is determined; some die
//! before any byte is sent); the JSON encoder omits fields that are
//! `None` so downstream queries don't need to special-case nulls.
//!
//! Writes are line-buffered through an [`AccessLogger`] backed by a
//! single appender task that batches `write_all` syscalls. The
//! appender uses `O_APPEND` semantics so multiple processes (e.g.
//! during a graceful restart) can share the same file without
//! interleaving partial lines.

use std::path::Path;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// One access-log record. All fields are optional from the emitter's
/// perspective; serialization skips `None` fields.
#[derive(Debug, Clone, Default)]
pub struct AccessLogRecord {
    /// Authenticated user id (8 bytes). Rendered as the original
    /// UTF-8 string when valid, otherwise as the hex-encoded bytes.
    pub user_id: Option<[u8; 8]>,
    /// Peer socket address as observed at TCP accept.
    pub peer: Option<std::net::SocketAddr>,
    /// Wall-clock session duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Plaintext bytes the server sent inside the inner stream.
    pub tx_bytes: Option<u64>,
    /// Plaintext bytes the server received from the inner stream.
    pub rx_bytes: Option<u64>,
    /// Short descriptor for *why* the session ended. Conventional
    /// values: `"upstream_eof"`, `"client_close"`, `"idle_timeout"`,
    /// `"upstream_dial_fail"`, `"relay_error"`, `"handler_panic"`.
    pub close_reason: Option<&'static str>,
    /// Shape-shift PRG seed the client picked (spec §22). Useful for
    /// forensic correlation across a session: two access-log lines
    /// with the same `shape_seed` were emitted by the same handshake.
    pub shape_seed: Option<u32>,
    /// Cover-profile selector the client picked (spec §22.4).
    pub cover_profile_id: Option<u16>,
}

impl AccessLogRecord {
    /// Render to a single canonical JSON line, with a trailing
    /// newline. The output is line-safe: no embedded `\n` in any
    /// value, and well-formed JSON parseable by any standard parser.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        // RFC 3339 timestamp in UTC. Hand-rolled to avoid pulling in
        // chrono / time as workspace deps; the format is fixed-width
        // and trivial.
        s.push_str(r#""ts":""#);
        push_rfc3339_now(&mut s);
        s.push('"');

        if let Some(uid) = self.user_id {
            push_kv_str(&mut s, "user_id", &format_user_id(&uid));
        }
        if let Some(peer) = self.peer {
            push_kv_str(&mut s, "peer", &peer.to_string());
        }
        if let Some(d) = self.duration_ms {
            push_kv_num(&mut s, "duration_ms", d);
        }
        if let Some(b) = self.tx_bytes {
            push_kv_num(&mut s, "tx_bytes", b);
        }
        if let Some(b) = self.rx_bytes {
            push_kv_num(&mut s, "rx_bytes", b);
        }
        if let Some(r) = self.close_reason {
            push_kv_str(&mut s, "close_reason", r);
        }
        if let Some(seed) = self.shape_seed {
            // Hex form so it's grep-friendly and the same width across
            // sessions (0x00000000 .. 0xffffffff).
            push_kv_str(&mut s, "shape_seed", &format!("0x{seed:08x}"));
        }
        if let Some(c) = self.cover_profile_id {
            push_kv_num(&mut s, "cover_profile_id", u64::from(c));
        }
        s.push('}');
        s.push('\n');
        s
    }
}

fn push_kv_str(out: &mut String, key: &str, value: &str) {
    out.push(',');
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    json_escape_into(value, out);
    out.push('"');
}

fn push_kv_num(out: &mut String, key: &str, value: u64) {
    out.push(',');
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

/// Encode the 8-byte user-id as UTF-8 when all bytes are printable
/// ASCII (32..127), otherwise as hex. Operators set `user_id` to
/// short ASCII strings (`"alice001"`) in practice; the hex fallback
/// is for paranoia.
fn format_user_id(bytes: &[u8; 8]) -> String {
    // Trim trailing NUL / space padding first ("alice\0\0\0" → "alice"),
    // then check whether the remainder is printable ASCII.
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    let trimmed = &bytes[..end];
    if !trimmed.is_empty() && trimmed.iter().all(|&b| (32..127).contains(&b)) {
        std::str::from_utf8(trimmed).unwrap_or("").to_string()
    } else {
        let mut s = String::with_capacity(16);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

/// Minimal JSON string-escape into an output buffer. Handles the
/// six characters JSON requires escaping (`"`, `\`, control bytes
/// `\b`, `\f`, `\n`, `\r`, `\t`, plus general `\uXXXX` for other
/// control bytes). The remaining UTF-8 sequences are emitted verbatim
/// (JSON strings are UTF-8 by spec).
fn json_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// RFC 3339 timestamp `YYYY-MM-DDTHH:MM:SS.sssZ` in UTC, appended.
fn push_rfc3339_now(out: &mut String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
    use std::fmt::Write;
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    );
}

/// Convert Unix-epoch seconds (proleptic Gregorian, UTC) to
/// `(year, month, day, hour, minute, second)`. Pure leap-year-aware
/// arithmetic; works for any year ≥ 1970. Adapted from the standard
/// "days since epoch" algorithm.
fn epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    const SECS_PER_DAY: u64 = 86_400;
    let days_since_epoch = secs / SECS_PER_DAY;
    let secs_today = (secs % SECS_PER_DAY) as u32;
    let hour = secs_today / 3600;
    let minute = (secs_today % 3600) / 60;
    let second = secs_today % 60;

    // Days since 0000-03-01 (Howard Hinnant's algorithm).
    let z = days_since_epoch as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (y + i64::from(month <= 2)) as u32;
    (year, month, day, hour, minute, second)
}

/// Handle for emitting access-log records. Cheap to clone (one
/// `Arc<mpsc::Sender>` increment).
#[derive(Clone)]
pub struct AccessLogger {
    tx: mpsc::Sender<AccessLogRecord>,
    /// Watch channel the writer task observes for reopen requests.
    /// We use Arc<tokio::sync::Notify> rather than a watch channel
    /// because all we need is "wake up and reopen now" — no payload.
    reopen: Arc<tokio::sync::Notify>,
    /// Path the writer reopens on signal. Stored so [`Self::reopen`]
    /// can be called without re-passing the path.
    path: Arc<std::path::PathBuf>,
}

impl AccessLogger {
    /// Open `path` for append and spawn the writer task. Returns a
    /// cloneable handle. The writer task lives for the lifetime of
    /// the process; closing the channel (drop-all-clones) makes it
    /// flush and exit.
    pub async fn spawn(path: &Path) -> std::io::Result<Self> {
        let path = Arc::new(path.to_path_buf());
        let file = open_append(&path).await?;
        let (tx, mut rx) = mpsc::channel::<AccessLogRecord>(1024);
        let reopen = Arc::new(tokio::sync::Notify::new());
        let reopen_task = Arc::clone(&reopen);
        let path_task = Arc::clone(&path);
        tokio::spawn(async move {
            // Coalesce: drain everything available before flushing so
            // a burst of session completions emits one write + one
            // fsync instead of N round trips. Single-record arrivals
            // still flush promptly (a stalled tail breaks the recv
            // loop, then we flush before exiting).
            let mut buf = tokio::io::BufWriter::with_capacity(64 * 1024, file);
            'outer: loop {
                tokio::select! {
                    biased;
                    // Reopen wakeups take priority over record drains
                    // so a rotation tool waiting for us to drop the
                    // old FD doesn't have to wait through a record
                    // burst.
                    () = reopen_task.notified() => {
                        if let Err(e) = buf.flush().await {
                            error!(error = %e, "access log flush before reopen failed");
                        }
                        match open_append(&path_task).await {
                            Ok(new_file) => {
                                buf = tokio::io::BufWriter::with_capacity(64 * 1024, new_file);
                                info!(path = ?path_task, "access log reopened (SIGUSR1)");
                            }
                            Err(e) => {
                                error!(error = %e, path = ?path_task, "access log reopen failed; keeping old FD");
                            }
                        }
                    }
                    maybe = rx.recv() => {
                        let rec = match maybe {
                            Some(r) => r,
                            None => break 'outer,
                        };
                        let line = rec.to_json_line();
                        if let Err(e) = buf.write_all(line.as_bytes()).await {
                            error!(error = %e, "access log write failed");
                            break 'outer;
                        }
                        // Drain the rest of the channel non-blockingly so we
                        // batch bursty arrivals into one flush.
                        while let Ok(rec) = rx.try_recv() {
                            let line = rec.to_json_line();
                            if let Err(e) = buf.write_all(line.as_bytes()).await {
                                error!(error = %e, "access log write failed");
                                break 'outer;
                            }
                        }
                        if let Err(e) = buf.flush().await {
                            error!(error = %e, "access log flush failed");
                            break 'outer;
                        }
                    }
                }
            }
            if let Err(e) = buf.flush().await {
                error!(error = %e, "access log final flush failed");
            }
        });
        Ok(Self { tx, reopen, path })
    }

    /// Best-effort: enqueue a record. Returns `false` if the channel
    /// is full (writer can't keep up) or the writer task has exited.
    /// Caller MUST treat this as advisory — never panic on a failed
    /// log write.
    pub fn log(&self, rec: AccessLogRecord) -> bool {
        match self.tx.try_send(rec) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("access log channel full; dropping record");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Ask the writer to flush, close the current FD, and reopen
    /// `path`. Called from a SIGUSR1 handler. Idempotent and safe to
    /// call from any thread; the actual reopen happens inside the
    /// writer task so there's no torn-write race.
    ///
    /// If the reopen fails (e.g. the new path is unwritable), the
    /// writer logs an error and keeps using the OLD FD — production
    /// keeps running, the operator gets a chance to fix the issue
    /// and signal again.
    pub fn reopen(&self) {
        self.reopen.notify_one();
    }

    /// Return the path the writer is currently configured to reopen.
    /// Used by tests to assert reopen semantics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

async fn open_append(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

/// Trait alias for a cloneable type the relay can use as an injected
/// logger. Allows test code to substitute an in-memory collector.
pub trait LogSink: Send + Sync {
    fn log(&self, rec: AccessLogRecord);
}

impl LogSink for AccessLogger {
    fn log(&self, rec: AccessLogRecord) {
        let _ = AccessLogger::log(self, rec);
    }
}

/// Type-erased handle for the relay to inject.
pub type AccessLogHandle = Arc<dyn LogSink>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_minimal() {
        let r = AccessLogRecord::default();
        let line = r.to_json_line();
        assert!(line.starts_with("{\"ts\":\""));
        assert!(line.ends_with("}\n"));
        // Parse back with a sanity check on shape.
        let body = &line[..line.len() - 1]; // strip newline
        assert!(body.starts_with('{') && body.ends_with('}'));
    }

    #[test]
    fn json_includes_all_fields() {
        let r = AccessLogRecord {
            user_id: Some(*b"alice001"),
            peer: Some("203.0.113.42:54321".parse().unwrap()),
            duration_ms: Some(12345),
            tx_bytes: Some(1024),
            rx_bytes: Some(2048),
            close_reason: Some("upstream_eof"),
            shape_seed: Some(0xdead_beef),
            cover_profile_id: Some(2),
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""user_id":"alice001""#));
        assert!(line.contains(r#""peer":"203.0.113.42:54321""#));
        assert!(line.contains(r#""duration_ms":12345"#));
        assert!(line.contains(r#""tx_bytes":1024"#));
        assert!(line.contains(r#""rx_bytes":2048"#));
        assert!(line.contains(r#""close_reason":"upstream_eof""#));
        assert!(line.contains(r#""shape_seed":"0xdeadbeef""#));
        assert!(line.contains(r#""cover_profile_id":2"#));
    }

    #[test]
    fn shape_fields_are_omitted_when_unset() {
        // Backward compat: legacy clients (or tests) that never set
        // shape_seed must not get spurious `null` fields in the log.
        let r = AccessLogRecord {
            user_id: Some(*b"alice001"),
            ..AccessLogRecord::default()
        };
        let line = r.to_json_line();
        assert!(!line.contains("shape_seed"));
        assert!(!line.contains("cover_profile_id"));
    }

    #[test]
    fn json_escapes_special_chars_in_user_id() {
        // Non-printable bytes → hex fallback.
        let r = AccessLogRecord {
            user_id: Some([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc]),
            ..AccessLogRecord::default()
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""user_id":"00010203fffefdfc""#));
    }

    #[test]
    fn json_trims_nul_padded_user_id() {
        let r = AccessLogRecord {
            user_id: Some(*b"alice\0\0\0"),
            ..AccessLogRecord::default()
        };
        let line = r.to_json_line();
        assert!(line.contains(r#""user_id":"alice""#));
    }

    #[test]
    fn json_escape_handles_dangerous_chars() {
        let mut out = String::new();
        json_escape_into("foo\"bar\\baz\nqux\t", &mut out);
        assert_eq!(out, "foo\\\"bar\\\\baz\\nqux\\t");
    }

    #[test]
    fn json_escape_handles_control_chars() {
        let mut out = String::new();
        json_escape_into("\x01\x1f", &mut out);
        assert_eq!(out, "\\u0001\\u001f");
    }

    #[test]
    fn rfc3339_includes_t_separator_and_z_suffix() {
        let mut out = String::new();
        push_rfc3339_now(&mut out);
        assert!(out.contains('T'), "missing T separator: {out}");
        assert!(out.ends_with('Z'), "missing Z suffix: {out}");
        assert!(
            out.len() == 24,
            "expected fixed-width RFC 3339, got {} chars: {out}",
            out.len()
        );
    }

    #[test]
    fn epoch_to_ymdhms_known_values() {
        // 2024-01-01T00:00:00Z = 1_704_067_200.
        let (y, m, d, h, min, s) = epoch_to_ymdhms(1_704_067_200);
        assert_eq!((y, m, d, h, min, s), (2024, 1, 1, 0, 0, 0));
        // 2026-05-16T00:00:00Z = 1_778_889_600.
        let (y, m, d, _, _, _) = epoch_to_ymdhms(1_778_889_600);
        assert_eq!((y, m, d), (2026, 5, 16));
        // Leap-year edge: 2024-02-29T00:00:00Z = 1_709_164_800.
        let (y, m, d, _, _, _) = epoch_to_ymdhms(1_709_164_800);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn access_logger_writes_to_disk() {
        let dir = std::env::temp_dir().join(format!("proteus-acclog-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("access.log");
        let logger = AccessLogger::spawn(&path).await.unwrap();
        for i in 0..3u8 {
            logger.log(AccessLogRecord {
                user_id: Some(*b"testuser"),
                duration_ms: Some(u64::from(i)),
                close_reason: Some("upstream_eof"),
                ..AccessLogRecord::default()
            });
        }
        // Drop the handle so the writer task drains + flushes + exits.
        drop(logger);
        // Give it a few ms to flush.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 lines, got: {body}");
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(r#""user_id":"testuser""#));
            assert!(line.contains(&format!(r#""duration_ms":{i}"#)));
            assert!(line.contains(r#""close_reason":"upstream_eof""#));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Logrotate-style scenario: a rotation tool renames the current
    /// log file out from under us, then sends SIGUSR1. The writer
    /// must reopen the original path (now a fresh empty file) and
    /// continue writing to the NEW inode. The original file (now
    /// renamed) must retain only the pre-reopen records.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reopen_after_rename_writes_to_new_file() {
        let dir = std::env::temp_dir().join(format!(
            "proteus-acclog-reopen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.log");
        let rotated = dir.join("access.log.1");

        let logger = AccessLogger::spawn(&path).await.unwrap();

        // Write 2 records, wait for flush.
        for i in 0..2u8 {
            logger.log(AccessLogRecord {
                user_id: Some(*b"pre_rotn"),
                duration_ms: Some(u64::from(i)),
                ..AccessLogRecord::default()
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // External rotation: rename current file aside.
        std::fs::rename(&path, &rotated).unwrap();

        // Without reopen, further writes would still hit the renamed
        // inode. Signal reopen and wait briefly for the writer task
        // to pick it up.
        logger.reopen();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Write 3 more records — these must land in the NEW file at `path`.
        for i in 0..3u8 {
            logger.log(AccessLogRecord {
                user_id: Some(*b"post_rot"),
                duration_ms: Some(u64::from(i + 10)),
                ..AccessLogRecord::default()
            });
        }
        drop(logger);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let new_body = std::fs::read_to_string(&path).unwrap();
        let new_lines: Vec<_> = new_body.lines().collect();
        assert_eq!(
            new_lines.len(),
            3,
            "new file should hold exactly the post-rotation records, got: {new_body}"
        );
        for line in &new_lines {
            assert!(
                line.contains(r#""user_id":"post_rot""#),
                "wrong record in new file: {line}"
            );
        }

        let old_body = std::fs::read_to_string(&rotated).unwrap();
        let old_lines: Vec<_> = old_body.lines().collect();
        assert_eq!(
            old_lines.len(),
            2,
            "rotated file should hold exactly the pre-rotation records, got: {old_body}"
        );
        for line in &old_lines {
            assert!(
                line.contains(r#""user_id":"pre_rotn""#),
                "wrong record in rotated file: {line}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reopen_is_idempotent_and_path_accessor_works() {
        let dir = std::env::temp_dir().join(format!(
            "proteus-acclog-idem-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.log");

        let logger = AccessLogger::spawn(&path).await.unwrap();
        assert_eq!(logger.path(), path.as_path());

        // Multiple reopens in a row must not panic / deadlock.
        for _ in 0..5 {
            logger.reopen();
        }
        // Records still land.
        logger.log(AccessLogRecord {
            user_id: Some(*b"survives"),
            ..AccessLogRecord::default()
        });
        drop(logger);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(r#""user_id":"survives""#));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
