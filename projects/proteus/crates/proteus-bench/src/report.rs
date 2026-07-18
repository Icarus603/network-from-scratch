//! Structured JSON report emitted by `proteus-bench client`.
//!
//! One line per run, stable schema. Designed for `jq` post-processing
//! into CSV for plotting throughput-vs-loss curves. Fields are stable
//! across releases — additions only, no renames or type changes —
//! so a netem-sweep script captured today still parses next year.

use std::fmt::Write as _;

/// Single run report. All numeric fields are concrete types (no
/// `Option`) so the JSON shape is rectangular and dead-simple to
/// pipe into Pandas / DuckDB.
#[derive(Debug, Clone)]
pub struct RunReport {
    /// Profile under test: `"alpha"` or `"beta"`.
    pub profile: &'static str,
    /// Total bytes pushed through (one direction; the harness echoes
    /// so wire bytes are 2× this).
    pub payload_bytes: u64,
    /// Per-`send_record` chunk size used by the client.
    pub chunk_bytes: u64,
    /// Wall clock between first send and last echoed byte received.
    pub elapsed_secs: f64,
    /// One-way effective throughput: `payload_bytes / elapsed_secs`.
    /// This is what we report as headline MiB/s.
    pub mib_per_sec: f64,
    /// Same number expressed as Gbps to match Hy2 / TUIC marketing
    /// numbers without forcing a calculator on the reader.
    pub gbps: f64,
    /// Server peer address (so an operator sweeping multiple
    /// candidate servers can correlate without separate run-naming).
    pub server_addr: String,
    /// Active PerfProfile knobs (β only; "n/a" for α).
    pub perf_profile: String,
    /// β idle-timeout configured for the run.
    pub idle_timeout_secs: u64,
    /// β connect timeout configured for the run.
    pub connect_timeout_secs: u64,
    /// Packets observed/dropped by the in-process impairment
    /// forwarder. Zero when no forwarder is active. These counters
    /// make every persisted result self-auditing: a `loss=30%`
    /// label without corresponding drops is no longer accepted as
    /// evidence.
    pub netem_c2s_packets_received: u64,
    pub netem_c2s_packets_dropped: u64,
    pub netem_s2c_packets_received: u64,
    pub netem_s2c_packets_dropped: u64,
}

impl RunReport {
    /// Hand-rolled JSON emitter. Single line, ends with `\n`. Stable
    /// field order (matches the struct definition) so consumers can
    /// rely on positional parsing if they want.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        push_str_field(&mut s, "profile", self.profile, true);
        push_u64_field(&mut s, "payload_bytes", self.payload_bytes, false);
        push_u64_field(&mut s, "chunk_bytes", self.chunk_bytes, false);
        push_f64_field(&mut s, "elapsed_secs", self.elapsed_secs, false);
        push_f64_field(&mut s, "mib_per_sec", self.mib_per_sec, false);
        push_f64_field(&mut s, "gbps", self.gbps, false);
        push_str_field(&mut s, "server_addr", &self.server_addr, false);
        push_str_field(&mut s, "perf_profile", &self.perf_profile, false);
        push_u64_field(&mut s, "idle_timeout_secs", self.idle_timeout_secs, false);
        push_u64_field(
            &mut s,
            "connect_timeout_secs",
            self.connect_timeout_secs,
            false,
        );
        push_u64_field(
            &mut s,
            "netem_c2s_packets_received",
            self.netem_c2s_packets_received,
            false,
        );
        push_u64_field(
            &mut s,
            "netem_c2s_packets_dropped",
            self.netem_c2s_packets_dropped,
            false,
        );
        push_u64_field(
            &mut s,
            "netem_s2c_packets_received",
            self.netem_s2c_packets_received,
            false,
        );
        push_u64_field(
            &mut s,
            "netem_s2c_packets_dropped",
            self.netem_s2c_packets_dropped,
            false,
        );
        s.push_str("}\n");
        s
    }
}

fn push_str_field(s: &mut String, k: &str, v: &str, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str(r#"":""#);
    // Escape only the characters JSON forbids in a quoted string. The
    // harness never emits raw control chars in these fields (peer
    // addresses are ASCII, perf-profile descriptors are ASCII) so the
    // minimal escape set is sufficient.
    for c in v.chars() {
        match c {
            '"' => s.push_str(r#"\""#),
            '\\' => s.push_str(r#"\\"#),
            '\n' => s.push_str(r#"\n"#),
            '\r' => s.push_str(r#"\r"#),
            '\t' => s.push_str(r#"\t"#),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, r#"\u{:04x}"#, c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn push_u64_field(s: &mut String, k: &str, v: u64, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str(r#"":"#);
    let _ = write!(s, "{v}");
}

fn push_f64_field(s: &mut String, k: &str, v: f64, first: bool) {
    if !first {
        s.push(',');
    }
    s.push('"');
    s.push_str(k);
    s.push_str(r#"":"#);
    // 4 decimal places: enough for throughput-curve plotting (a
    // 0.0001 MiB/s difference is below run-to-run noise), small
    // enough that the line stays under terminal-width.
    let _ = write!(s, "{v:.4}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RunReport {
        RunReport {
            profile: "beta",
            payload_bytes: 16 * 1024 * 1024,
            chunk_bytes: 64 * 1024,
            elapsed_secs: 0.2,
            mib_per_sec: 80.0,
            gbps: 0.64,
            server_addr: "203.0.113.4:443".to_string(),
            perf_profile: "padding=off,initial_mtu=1200".to_string(),
            idle_timeout_secs: 60,
            connect_timeout_secs: 5,
            netem_c2s_packets_received: 0,
            netem_c2s_packets_dropped: 0,
            netem_s2c_packets_received: 0,
            netem_s2c_packets_dropped: 0,
        }
    }

    #[test]
    fn json_is_single_line_with_trailing_newline() {
        let j = sample().to_json();
        assert!(
            j.ends_with('\n'),
            "JSON must end with newline for streaming-jq compatibility: {j:?}"
        );
        // Strip the trailing newline and check no embedded ones.
        let core = &j[..j.len() - 1];
        assert!(
            !core.contains('\n'),
            "JSON body must not contain newlines (line-delimited format): {core:?}"
        );
    }

    #[test]
    fn json_contains_every_field_in_stable_order() {
        let j = sample().to_json();
        // Index-based ordering check: each field appears in the
        // documented sequence. Future additions must come AFTER
        // these positions to preserve append-only stability.
        let positions: Vec<_> = [
            r#""profile""#,
            r#""payload_bytes""#,
            r#""chunk_bytes""#,
            r#""elapsed_secs""#,
            r#""mib_per_sec""#,
            r#""gbps""#,
            r#""server_addr""#,
            r#""perf_profile""#,
            r#""idle_timeout_secs""#,
            r#""connect_timeout_secs""#,
            r#""netem_c2s_packets_received""#,
            r#""netem_c2s_packets_dropped""#,
            r#""netem_s2c_packets_received""#,
            r#""netem_s2c_packets_dropped""#,
        ]
        .iter()
        .map(|needle| {
            j.find(needle)
                .unwrap_or_else(|| panic!("missing {needle} in {j}"))
        })
        .collect();
        for w in positions.windows(2) {
            assert!(
                w[0] < w[1],
                "field order regression: positions {:?} for {j}",
                positions
            );
        }
    }

    #[test]
    fn json_escapes_quotes_in_string_fields() {
        let mut r = sample();
        r.server_addr = r#"host"with"quotes:443"#.to_string();
        let j = r.to_json();
        assert!(
            j.contains(r#"host\"with\"quotes:443"#),
            "should escape quotes: {j}"
        );
    }

    #[test]
    fn json_escapes_backslashes_in_string_fields() {
        let mut r = sample();
        r.perf_profile = r"win\slash".to_string();
        let j = r.to_json();
        assert!(j.contains(r"win\\slash"), "should escape backslashes: {j}");
    }

    #[test]
    fn json_emits_throughput_to_four_decimals() {
        // 0.12345 should appear as 0.1235 (round half to even / nearest
        // depending on platform — both acceptable; the test just
        // confirms the precision IS 4 places, not 17).
        let r = RunReport {
            profile: "beta",
            payload_bytes: 1,
            chunk_bytes: 1,
            elapsed_secs: 0.12345,
            mib_per_sec: 7.123456,
            gbps: 0.0568,
            server_addr: "x".into(),
            perf_profile: "y".into(),
            idle_timeout_secs: 1,
            connect_timeout_secs: 1,
            netem_c2s_packets_received: 0,
            netem_c2s_packets_dropped: 0,
            netem_s2c_packets_received: 0,
            netem_s2c_packets_dropped: 0,
        };
        let j = r.to_json();
        assert!(
            j.contains(r#""elapsed_secs":0.1234"#) || j.contains(r#""elapsed_secs":0.1235"#),
            "{j}"
        );
        assert!(
            j.contains(r#""mib_per_sec":7.1235"#) || j.contains(r#""mib_per_sec":7.1234"#),
            "{j}"
        );
    }

    #[test]
    fn json_handles_empty_strings() {
        let mut r = sample();
        r.server_addr = String::new();
        r.perf_profile = String::new();
        let j = r.to_json();
        assert!(j.contains(r#""server_addr":"""#), "{j}");
        assert!(j.contains(r#""perf_profile":"""#), "{j}");
    }
}
