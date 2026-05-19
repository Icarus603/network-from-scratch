# Changelog

All notable changes to the Proteus reference implementation.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we hit `1.0.0`. Pre-1.0 minor bumps may include breaking changes;
patch bumps are bug-fix only.

## [Unreleased] — production-stability iteration arc (post-0.1.0)

This window covers the M2 production-stability work between v0.1.0
and the next tagged release. Iteration numbers in commit messages
correspond to the Ralph Loop iteration counter; they are
implementation-internal, not user-visible. The user-visible groupings
below are organised by concern.

### Changed — α cell-split send path: skip zero-fill on non-terminal cells (iter-150)

Micro-optimization on the α cell-padded send path. Pre-iter-150
EVERY cell did `tx_aead_scratch.resize(quantum, 0)` to zero-fill
the scratch buffer to `quantum` bytes before writing the cell's
prefix + chunk. For NON-terminal cells this zero-fill was pure
waste: `chunk.len() == chunk_max` always, so the layout is
exactly `[4-byte sentinel | chunk_max bytes] = quantum bytes` —
every byte gets overwritten by the `copy_from_slice` calls
immediately after.

Iter-150 splits the branches:

- **Non-terminal cells**: build via `extend_from_slice(sentinel)
  + extend_from_slice(chunk)`. Two appends, zero pre-fill,
  total length lands at `quantum` exactly. Debug-assert pins
  the length invariant.
- **Terminal cells**: keep the existing `resize(quantum, 0) +
  targeted overwrites` pattern since the post-chunk region
  must be zero-padded.

Win scales linearly with `quantum`. At `pad_quantum = 1280` on
a bulk-download workload (16 KiB logical payload → ~12-13
non-terminal cells + 1 terminal), this saves:

- 12 memsets × 1280 bytes ≈ 15 KiB of memset work PER record
- 12 cache-line evictions PER record (each memset touches
  20+ cache lines)

AEAD encrypt remains the dominant cost on the cell path (~80%
of CPU time per cell), but every saved memset is a free
L1-cache cycle that the bench's "MiB/s" number will reflect
under sustained load.

Wire format is byte-identical (the AEAD inputs — key, nonce,
AAD, plaintext — are unchanged; only the SCRATCH initialization
strategy changed). The existing
`cell_split_padding::multi_cell_payload_splits_and_reassembles_correctly`
integration test covers end-to-end byte equivalence and still
passes — no regression test specifically for iter-150 needed
because the wire-format contract IS the regression test.

All 452 α unit tests + workspace tests green. clippy + fmt clean.

### Changed — `restart_tracker::save` adds fsync for crash durability (iter-149)

Sibling to iter-148. The server's restart-tracker persists
`(restart_count, first_start_unix, last_clean_shutdown_unix,
previous_start_unix, previous_end_reason)` to a JSON file so
operators see `proteus_restarts_total` survive across systemd
restarts — the bedrock for the
`rate(proteus_restarts_total[1h]) > 1` crash-loop alert.

Pre-iter-149 `save` used the standard temp-file-then-rename
pattern but, like the iter-148 user_quota / user_quarantine
paths, lacked fsync between write and rename + lacked
parent-dir fsync after rename. POSIX rename atomicity is at
the directory-entry layer; the file's data pages can still be
unwritten when a crash happens. Reload then sees a
default-everything tracker → `restart_count = 0` permanently,
defeating the crash-loop alert.

Iter-149 adds the same sequence the iter-148 modules use:
write tmp → `tmp.sync_all()` → rename → `parent.sync_all()`.
Best-effort throughout (errors log at WARN; in-memory state
stays authoritative).

Deliberately does NOT chmod the file — restart state contains
no PII (just counters + unix timestamps); operators reading
`/var/lib/proteus/restart_state.json` expect it to be readable.

All 10 restart_tracker tests + workspace tests green.

### Security — `user_quota` + `user_quarantine` persist files: fsync + mode 0600 (iter-148)

Two durability + privacy gaps on the per-user state persistence
paths (`user_quota::persist`, `user_quarantine::persist`). Both
use the temp-file-then-rename pattern for atomicity, but
pre-iter-148:

- **No fsync between write and rename.** POSIX rename is atomic
  at the directory-entry layer but the file's DATA pages aren't
  guaranteed to be on disk. A host crash between the write and
  the kernel's writeback can leave a directory entry pointing
  at an empty file. On reload the operator sees empty quota /
  empty quarantine state → every user gets a fresh allotment
  AND every quarantine ban evaporates. The latter is worse:
  the iter-quarantine list is designed to survive process
  restarts specifically so a stolen credential can't bypass
  the ban via a forced systemd cycle.
- **Mode 0644 (world-readable) on the final file.** The temp
  file inherits the operator's umask (0022 typical → 0644
  final). The persisted state contains operator-chosen
  `user_id` strings (`"alice001"`, `"bob_finance_team"`,
  `"company-eu-team"`) — on a multi-tenant / shared host these
  are PII the operator wouldn't want any local user to read.
  Per-user bandwidth + cap_override + ban-trigger metadata
  is also leaked.

Iter-148 closes both gaps on BOTH persist paths via the same
sequence: write tmp → re-open + `sync_all()` → chmod 0600 →
rename → parent-dir `sync_all()`.

The chmod runs BEFORE rename so a concurrent reader of the
final path never sees a 0644 atomicity window. Same pattern
SQLite uses for its commit machinery.

All four operations are best-effort: errors get logged at
WARN but don't fail the persist. The in-memory state remains
authoritative; a missing fsync just narrows the durability
window, and a chmod failure just lifts the privacy gate (still
safer than refusing to persist at all).

2 new tests pin the mode-0600 invariant:
- `user_quota::tests::iter148_persist_file_is_mode_0600`
- `user_quarantine::tests::iter148_persist_file_is_mode_0600`

We can't directly observe fsync from the test harness, but the
existing persist + reload tests confirm the write + rename
sequence still produces a readable file post-rename.

All workspace tests green. clippy + fmt clean.

### Security — `parse_http_url` rejects control bytes in host + path (iter-147)

Defense-in-depth on the three `parse_http_url` parsers that the
admin CLI surfaces use to build HTTP GET requests:

- `proteus-server::admin::parse_http_url` (`admin status`,
  `admin diff`, `admin abuse-fires`, `admin alerts-check`, etc.)
- `proteus-client::admin_alerts_check::parse_http_url`
  (`proteus-client alerts-check`)
- `proteus-client::main::parse_http_url` (`proteus-client status`,
  `diagnose`, `connect-test`)

Pre-iter-147 each parser only validated the scheme prefix +
port-as-u16. A `--url` argument containing CRLF / NUL / TAB
anywhere in the host or path got embedded verbatim into the
HTTP request line + Host: header in the subsequent `http_get`,
enabling HTTP request smuggling via attacker-chosen headers:

```
proteus-server admin status \
    --url 'http://127.0.0.1\r\nX-Smuggle: yes:9090/metrics'
```

would emit:

```
GET /metrics HTTP/1.1
Host: 127.0.0.1
X-Smuggle: yes:9090
User-Agent: proteus-admin
Connection: close
```

Threat model: the URL is operator-supplied, so this is mostly
"attack self". But config-templating tools that pull URLs from
untrusted sources (Ansible templates fetching from a misconfigured
inventory, k8s ConfigMaps with operator-injected fields) could
turn this into a remote-injection path. Closing the gate is
correct defense-in-depth regardless.

Iter-147 adds the same reject pattern to all three parsers:

- Reject host containing NUL / CR / LF / TAB / space.
- Reject path containing NUL / CR / LF / TAB.

Error message names "forbidden control character" + the actionable
remediation ("strip the offending byte from the --url argument").

4 new tests in `proteus-server::admin::tests`:
- `iter147_parse_http_url_rejects_crlf_in_host` (4 control bytes)
- `iter147_parse_http_url_rejects_crlf_in_path` (4 control bytes)
- `iter147_parse_http_url_rejects_space_in_host`
- `iter147_well_formed_urls_still_parse_cleanly` (positive case
  with 4 legit URL shapes)

The two client-side parsers don't have dedicated iter-147 tests
because the gate logic is byte-identical to the server-side and
their `parse_http_url` is already covered by smoke tests that
the well-formed `http://127.0.0.1:9091/...` form keeps parsing.

All workspace tests green. clippy + fmt clean.

### Security — `parse_connect` validates inner CONNECT host + port (iter-146)

The server's inner-protocol CONNECT request (parsed by
`relay::parse_connect` after the Proteus handshake authenticates)
flows directly into `tokio::net::lookup_host` →
`OutboundPolicy::check` → `TcpStream::connect`. Pre-iter-146 the
parser only validated UTF-8 + buffer length; it accepted
several malformed shapes that lead to real production issues:

- **`host_len = 0`** → empty hostname passes through to
  `lookup_host("":port)`, which wastes the full 5-second
  DNS-bound-timeout window. A malicious authenticated client
  could DoS the relay's resolver budget by spraying empty-host
  CONNECTs.
- **NUL byte in hostname** (`evil.com\0safe.local`) → classic
  CWE-367 (time-of-check vs time-of-use). Some libcs treat
  hostnames as C-strings and TRUNCATE at the first `\0`; the
  outbound_filter sees the full `evil.com\0safe.local` string,
  but the system resolver only sees `evil.com`. Operator's
  SSRF policy that blocks `evil.com` would still permit the
  dial through this confusion.
- **CR / LF / TAB in hostname** → HTTP request smuggling
  defense-in-depth. If the downstream destination is an HTTP
  server that uses the hostname in a header (most do —
  reverse-proxy Host:), the CRLF allows a malicious client to
  inject arbitrary headers into the upstream request.
- **`port = 0`** → not a connectable TCP port. The connect
  fails at the socket layer with `EADDRNOTAVAIL` or similar;
  rejecting at parse time gives a clearer diagnostic.

Iter-146 adds the validation pass:

- Reject `host_len == 0` with "connect host is empty".
- Defensively reject `host_len > 255` (currently impossible
  given the u8 prefix, but defense-in-depth for future
  protocol changes).
- Reject any host containing `\0` / `\r` / `\n` / `\t` with
  "connect host contains forbidden control byte".
- Reject `port == 0`.

9 new tests in `parse_connect_tests`:
- `well_formed_connect_parses` — sanity baseline.
- `empty_buf_rejected` — preserved legacy behavior.
- `empty_host_rejected` — new iter-146 gate.
- `port_zero_rejected` — new iter-146 gate.
- `nul_in_host_rejected` — CWE-367 defense.
- `crlf_in_host_rejected` — three variants (CR / LF / TAB).
- `truncated_buf_rejected` — preserved legacy behavior.
- `non_utf8_host_rejected` — preserved legacy behavior.
- `common_legit_destinations_pass` — IPv4 literal, IPv6
  bracket literal, common-port domain names; the positive
  side of the new gate.

All workspace tests green. clippy + fmt clean.

### Fixed — access-log writer fsyncs the final batch on graceful exit (iter-145)

Audit-log durability gap. The access-log writer task ran its
steady-state hot loop with `BufWriter::flush()` — that writes
pending bytes to the kernel buffer (via `write(2)`) but does
**not** call `fsync(2)`. The final shutdown branch:

```rust
'outer: loop { ... }
stats_task.writer_alive.store(false, Ordering::Relaxed);
if let Err(e) = buf.flush().await {
    stats_task.write_errors.fetch_add(1, Ordering::Relaxed);
    error!(error = %e, "access log final flush failed");
}
```

…also only flushed. An operator workflow that exposes the gap:

1. `systemctl stop proteus-server` → SIGTERM.
2. drain runs, writer's mpsc rx side gets dropped, writer
   exits the loop, runs final flush — bytes hit the kernel
   buffer.
3. systemd reports `inactive (dead)` — operator believes the
   binary "exited cleanly, audit log is complete".
4. Host hits a kernel panic / hard power-off in the next
   ~30 s (Linux `vm.dirty_writeback_centisecs` default).
5. Page cache never flushes to disk. The last batch of
   audit records — every session that completed in the
   final drain window — is lost.

For a security-audit log that's the wrong durability story.
Iter-145 closes the gap on the FINAL flush only (steady-state
flushes still skip fsync to preserve hot-path throughput):

```rust
if let Err(e) = buf.flush().await { ... }
// ITER-145: convert BufWriter back into the tokio File and
// fsync the final batch so audit records committed during
// drain survive a host crash that lands between SIGTERM-ack
// and the next writeback cycle.
let file = buf.into_inner();
if let Err(e) = file.sync_data().await { ... }
```

`into_inner()` is safe here — `buf` was just flushed, so the
underlying File holds no pending bytes. `sync_data` instead of
`sync_all` because we only need the audit log's data + length
metadata to survive; the file's mtime / ctime don't matter for
audit-trail integrity, so we save the extra inode-metadata
sync that `sync_all` performs.

Trade-off rationale (why fsync on exit only, not on every batch):

- Steady-state batches in the hot loop are bursty (many
  session closes per second under load). fsync on every batch
  would serialize the writer task on the disk and could
  noticeably affect data-plane throughput on small VPSes.
- The FINAL flush is the operationally critical one: it
  represents "everything the operator expects to be persisted
  by the time systemd stop returns". Adding one fsync on the
  shutdown path costs one syscall on shutdown; irrelevant.

1 new regression test (`iter145_final_flush_fsync_does_not_panic_and_records_survive_drop`)
exercises the drop→flush→fsync path with 5 records: pre-iter-145
the records hit the page cache via flush but a future regression
that moved sync_data BEFORE flush (or threw on into_inner) would
panic the writer task; the test asserts the file is readable
post-drop with every record present.

All 449 α unit tests + workspace tests green. clippy + fmt clean.

### Fixed — `proteus-server validate` length-gates server X25519 key files (iter-144)

Completing the server-side key-bytes integrity check arc started
in iter-140 (ML-KEM) and continued in iter-143 (ed25519_pk). The
last unprotected key file on the server side was the static
X25519 keypair (`keys.x25519_pk` + `keys.x25519_sk`):

- **`x25519_sk` truncated** → server panics on `StaticSecret::from`
  during startup. systemd restart loop, opaque crash signal.
- **`x25519_pk` truncated** → the bytes load successfully (any
  32-byte slice is a "valid" X25519 public key from the parser's
  POV — RFC 7748 doesn't validate subgroup membership at the
  type level), but the DH output mismatches what the client
  computes. The server runs fine but **every client handshake
  fails the Finished MAC**. This is even harder to diagnose than
  the panic case because the server appears healthy.

Iter-144 adds `check_x25519_key_len` and wires it for both files.
Requires `raw.len() == 32` OR `base64_decode(raw).len() == 32`
(RFC 7748 §5). FAIL message names the field, both length numbers,
and the actionable remediation (`proteus-server keygen`).

4 new tests in `validate::tests`:
- `iter144_truncated_x25519_pk_fails`: 10-byte file → FAIL.
- `iter144_truncated_x25519_sk_fails`: same gate on the SK side.
- `iter144_oversized_x25519_pk_fails`: 64-byte file (operator
  copied an ed25519 keypair into the slot) → FAIL.
- `iter144_correct_length_x25519_passes_length_gate`: 32-byte
  file → no length FAIL.

Two test fixtures updated to the new gate
(`tests/validate_cli.rs::touch`,
`tests/validate_cert_expiry.rs::touch`) so the cert-expiry +
green-yaml-validates tests don't accidentally trip iter-144 with
their placeholder x25519 key files.

The server-side key-bytes integrity story is now complete: all 4
key file types (ML-KEM EK/DK + X25519 PK/SK + allowlist ed25519
PKs) have length + non-zero + (where applicable) duplicate-bytes
gates. Same coverage shape as the client side (iter-139).

All 133 server validate unit tests + workspace tests green.
clippy + fmt clean.

### Fixed — `proteus-server validate` length-gates allowlist ed25519_pk files (iter-143)

Sibling to iter-140 (ML-KEM key files) and iter-142 (duplicate
pubkey bytes). The third "wrong-key-bytes-passed-validate" trap
on the server side was the allowlist's `client_allowlist[*].ed25519_pk`:
the `check_file` gate only verified existence + non-all-zero, so
a truncated pubkey (operator scp-copied a partial file, base64
fragment from a half-paste, ed25519 SK accidentally copied into
the PK slot) passed validate clean.

Then at server startup, `ServerKeys::from_config` calls
`VerifyingKey::from_bytes(&pk_arr)` on the loaded bytes, which
returns `BadKey("ed25519_pk must be 32 bytes")` or
`BadKey("invalid ed25519_pk")`. The server's main fn surfaces
the error and exits non-zero. To the operator this looked like
"the server won't start, error mentions ed25519_pk" with no
hint that running validate first would have caught this AND
named the offending user_id.

Iter-143 inserts a length gate inline in the allowlist loop:

- Read each entry's `ed25519_pk` file (raw or base64-armored).
- Require EITHER `raw.len() == 32` OR `base64_decode(raw).len() == 32`.
- FAIL with both length numbers + the user_id in the message
  + an actionable remediation: "Re-issue with
  `proteus-client keygen --out keys/` and copy the resulting
  `client.ed25519.pk` into place."

Skip the gate when the file is absent or empty — those already
FAILED via check_file's existing checks; double-failing just
adds noise.

3 new tests in `validate::tests`:
- `iter143_truncated_allowlist_pk_fails`: 10-byte file → FAIL
  that names both the field AND the expected length.
- `iter143_oversized_allowlist_pk_fails`: 64-byte file (would
  be a leaked ed25519 SK in the worst case) → FAIL.
- `iter143_correct_length_allowlist_pk_passes_length_gate`:
  32-byte file → no length FAIL.

All 129 server validate unit tests + workspace tests green.
clippy + fmt clean.

### Fixed — `proteus-server validate` detects duplicate ed25519_pk bytes across allowlist user_ids (iter-142)

Pre-iter-142 the validate path checked for duplicate `user_id`
**strings** in `client_allowlist` (iter-57) but did NOT check for
duplicate `ed25519_pk` **bytes** across different user_ids. Two
distinct user_ids sharing the same pubkey content is the
**worst-case form** of allowlist typo because every existing
gate passes:

- Each file exists.
- Each parses as a valid ed25519 verifying key.
- The user_id strings differ, so the iter-57 dup-check passes.

But at runtime, ONE client SK can authenticate as EITHER user_id —
the server's allowlist iteration returns whichever entry sorted
first. Per-user accounting (`proteus_per_user_bytes_*`), per-user
quotas (`user_quotas.overrides`), per-user concurrent-session caps
(`per_user_conn_limit`), and the iter-quarantine list all silently
mis-attribute traffic to the first-matching user_id. Operators see
"alice's monthly quota is being consumed by bob's traffic" with no
hint that the underlying allowlist has the same pubkey twice.

Iter-142 adds a third allowlist gate alongside the iter-55
(file modes) + iter-57 (user_id duplication) checks:

- Read each `ed25519_pk` file (raw or base64-armored).
- Skip empty/zero/wrong-length entries (FAILED by other gates).
- HashMap-bucket the decoded 32-byte content; any bucket with >1
  user_id emits a FAIL listing all the colliding user_ids and the
  first 8 bytes of the shared pubkey as a triage hint.

FAIL message includes:
- The operator-actionable remediation tree: "(a) re-issue ONE of
  the user_ids with a fresh keypair (recommended; the original
  keypair was probably copied by accident), or (b) consolidate
  into a single user_id entry."

3 new tests in `validate::tests`:
- `iter142_duplicate_ed25519_pk_bytes_across_user_ids_fails`:
  two user_ids sharing the same pubkey → FAIL naming both
  user_ids.
- `iter142_distinct_ed25519_pk_bytes_do_not_fail`: distinct
  pubkeys → no false positive.
- `iter142_three_way_shared_pk_lists_all_users`: three-way
  share → FAIL must enumerate all three colliding user_ids.

The existing iter-57 tests still pass (they use short non-32-byte
files which the iter-142 check correctly skips, so no spurious
overlapping FAILs).

All 126 server validate tests + workspace tests green. clippy + fmt
clean.

### Fixed — `proteus-server validate` catches cover-endpoint non-TLS port footgun (iter-141)

The cover-forward path (spec §7.5) splices the raw inbound TLS
ClientHello bytes verbatim to the configured cover endpoint. The
cover endpoint MUST therefore be a TLS-speaking endpoint
(typically `:443`); pointing it at a plaintext-HTTP server
catastrophically defeats the cover arm. Active prober view:

1. Send a real-looking TLS ClientHello to the Proteus server.
2. Auth fails → cover-forward kicks in.
3. Proteus splices the ClientHello bytes to `cover_endpoint:80`.
4. The HTTP server on port 80 can't parse those bytes as HTTP →
   immediate error response with a non-TLS shape (likely
   `HTTP/1.1 400 Bad Request` + `Connection: close` or a
   malformed-byte-stream RST).
5. The prober compares the response shape against a real
   `curl https://www.example.com/`: doesn't match → **THIS IS
   NOT A REAL HTTPS SERVER**.

The entire REALITY/cover-passthrough defense collapses to "not
even trying". Pre-iter-141 nothing in the validate path flagged
this — operators copying `www.example.com` from a tutorial and
forgetting the `:443` got a silently-broken deploy.

Iter-141 adds port-sanity to both `cover_endpoint` and every
entry in `cover_endpoints[]`:

- **FAIL** on any of `{21, 22, 23, 25, 80}` — well-known
  plaintext-protocol ports (FTP/SSH/Telnet/SMTP/HTTP).
  Operator-actionable message: "DEFEATING the entire cover arm.
  Point cover_endpoint at an HTTPS endpoint (port 443)."
- **WARN** on any port outside `{443, 8443, 9443}` —
  acknowledges that custom-port TLS deploys exist, but flags
  the unusual choice so operators verify intent.
- **PASS** on the canonical TLS ports.

5 new tests in `validate::tests`:
- `iter141_cover_endpoint_port_80_fails`: the canonical case.
- `iter141_cover_endpoint_other_plaintext_ports_fail`: all of
  `{21, 22, 23, 25, 80}` hit the hard-fail branch.
- `iter141_cover_endpoint_canonical_tls_ports_pass`: 443 /
  8443 / 9443 don't trip the gate.
- `iter141_cover_endpoint_unusual_port_warns`: unusual port
  produces WARN with the field + port both named.
- `iter141_cover_endpoints_pool_port_80_fails`: pool entries
  hit the same gate; FAIL message indexes the bad entry
  (`cover_endpoints[1]`).

All 118 server validate unit tests + 5 new iter-141 tests pass.
Full workspace test suite green; clippy clean; fmt clean.

### Fixed — `proteus-server validate` tightens ML-KEM EK + DK length gates (iter-140)

Server-side sibling to iter-139 (which tightened the client's
`server_mlkem_pk` gate). The server has two ML-KEM key files to
worry about: the EK (`mlkem_pk`, 1184 bytes raw, published to
clients) and the DK (`mlkem_sk`, 2400 bytes raw, kept secret).
Pre-iter-140 the validate path only checked "file exists +
readable + not all-zero" — a truncated DK passed validate and
then either:

1. **Crashed the server on startup** when
   `DecapsulationKey::from_bytes` panicked on the malformed
   key. systemd restart loop, same opaque "server keeps
   crashing" symptom the iter-138 client fix targets on the
   other end.
2. **Generated a fingerprint that mismatched every client's
   pinned `server.pq.fingerprint`** if the EK was truncated
   but happened to parse cleanly (the keygen tool writes
   raw bytes; partial-write scenarios where the file is
   shorter than 1184 are the realistic failure mode).

Iter-140 adds `check_mlkem_key_len` and wires it for both
`keys.mlkem_pk` (1184 bytes) and `keys.mlkem_sk` (2400 bytes).
Accepts either raw bytes on disk OR base64-armored bytes
(decode via the existing `base64_or_raw_bytes`). FAIL message
names BOTH the field path AND the expected length AND the
likely operator action ("Regenerate with
`proteus-server keygen`"), so the operator running the
iter-122 mandatory preflight gate gets an immediately
actionable signal.

2 new tests in `validate_cli.rs`:
- `validate_fails_on_truncated_mlkem_ek`: 100-byte EK file →
  exit non-zero + stdout contains the field name `keys.mlkem_pk`
  + the expected length `1184`.
- `validate_fails_on_truncated_mlkem_dk`: same shape for the
  DK side.

Two existing test fixtures had to be updated to use realistic
key sizes:

- `validate.rs::tests::minimal_cfg` now writes 1184/2400-byte
  buffers (was `b"placeholder"` = 11 bytes).
- `tests/validate_cli.rs::touch` size-dispatches on the file
  name suffix.
- `tests/validate_cert_expiry.rs::touch` does the same so the
  cert-expiry tests don't accidentally trip the iter-140 gate.

All 118 server validate unit tests + 6 validate_cli integration
tests + the cert-expiry integration tests pass. Full workspace
test suite green; clippy clean; fmt clean.

### Fixed — `proteus-client validate` tightens ML-KEM EK length gate (iter-139)

Sibling to iter-138 on the validate-time defense layer. Pre-iter-139
the client validate path checked the `server_mlkem_pk` file with
the permissive predicate `|n| n >= 32` ("≥32 bytes"). That gate
passed every truncated EK an operator might have produced (typo
in `scp`, base64 partial paste, wrong file extension copied from
the deploy guide, etc.). The first signal of trouble was the
runtime BadServerKey error iter-138 added — same operator-actionable
information, but deferred from "validate says no" to "first dial
fails".

Iter-139 tightens the validate-time gate to "exactly 1184 bytes
raw OR ~1580-1592 bytes base64 (ML-KEM-768 EK; FIPS-203 §6.1)".
Operators editing `client.yaml` then running
`proteus-client validate --config ~/.proteus/client.yaml`
(the iter-122 mandatory preflight gate) now learn the EK is
wrong BEFORE any wire I/O — exit 1 with a FAIL row that names
the field. Symmetric with the iter-122/123/132 contract that
the preflight gate is authoritative for "is this deploy
fixable without rolling back".

The base64 range is `(EK_bytes × 4 + 3) / 3` rounded up plus
slack for trailing newlines, so 1580-1592 bytes covers
canonical-encoded EKs (`1184 * 4 / 3 = 1579`, plus one or two
trailing `\n` / `=` chars depending on encoder). The file is
decoded via the existing `decode_b64_or_raw` at runtime, so
either form on disk works.

2 new tests in `validate_cli.rs`:
- `truncated_mlkem_ek_fails_validate`: 64-byte file →
  FAIL row that names `server_mlkem_pk`.
- `correct_1184_mlkem_ek_passes_validate_length_gate`: green
  YAML's existing 1184-byte EK → no FAIL row mentions
  `server_mlkem_pk`.

All client tests green + full workspace test suite green +
workspace clippy clean. fmt clean.

### Fixed — client handshake panicked on malformed ML-KEM EK config (iter-138)

Pre-iter-138 the α client handshake (`client::handshake_over_split_bound`)
parsed the configured server ML-KEM-768 EK with:

```rust
let ek_array = ml_kem::array::Array::<u8, _>::try_from(
    &config.server_mlkem_pk_bytes[..]
).expect("mlkem pk");
```

A malformed `server_mlkem_pk_bytes` — operator typo in
`client.yaml`'s `server.mlkem_pk`, base64 decode dropping bytes,
truncated copy-paste from the deploy guide, etc. — panicked the
client binary. The panic hook caught it and bumped
`proteus_panics_total`, then systemd restarted the binary, then
the next dial attempt panicked again on the still-malformed
config. To the operator this looked like "the client just keeps
crashing" with no actionable signal pointing at the
configuration as the root cause.

Iter-138 surfaces a typed `AlphaError::BadServerKey(&'static str)`
instead:

- Length-gate first: ML-KEM-768 EK MUST be exactly 1184 bytes
  (FIPS-203 §6.1). A length mismatch surfaces an actionable
  error message naming both the expected length AND the
  configuration field to check
  (`"check `server.mlkem_pk` in client.yaml"`).
- Belt-and-braces: even at the correct length, if the
  underlying `Array::try_from` fails (which is impossible
  given the length matches the slice type, but defense-in-
  depth), the error is mapped into the same `BadServerKey`
  variant instead of unwinding.

The new error variant carries a `&'static str` detail string
so the validate / status surfaces can render the specific
failure (`"ML-KEM-768 EK length mismatch (expected 1184 bytes;
check \`server.mlkem_pk\` in client.yaml)"`) instead of an
opaque error code. Same shape as the existing
`BadServerFinished` / `BadClientFinished` / `AuthTagInvalid`
variants — operators get one place to look for handshake-
phase errors.

4 new integration tests in
`tests/malformed_server_key.rs` pin every failure mode the
EK parse can take:

- `empty_mlkem_pk_bytes_returns_bad_server_key_not_panic`:
  empty Vec → BadServerKey, NOT panic.
- `truncated_mlkem_pk_bytes_returns_bad_server_key`: 100
  bytes → BadServerKey.
- `oversized_mlkem_pk_bytes_returns_bad_server_key`: 4096
  bytes → BadServerKey.
- `correct_length_garbage_mlkem_pk_bytes_returns_bad_server_key_or_handshake_failure`:
  1184 bytes of zeros → the test's contract is "no panic",
  any Err is acceptable (the EK parse passes the length gate
  + the in-memory key parse succeeds; the failure surfaces
  later as a handshake error).

All 4 tests pass; full workspace test suite green. clippy
clean. fmt clean.

### Fixed — cover-forward dial applies keepalive + TCP_USER_TIMEOUT (iter-137)

Pre-iter-137 the cover-forward dial path (`cover::forward_to_cover`)
applied only `set_nodelay(true)` to the upstream socket. Keepalive
was off; on Linux `TCP_USER_TIMEOUT` was unset. That left an
amplification surface for the most operationally dangerous attack
shape in production:

1. Attacker floods the server with junk ClientHellos (each below
   the per-IP rate limiter, distributed across many IPs).
2. Each junk attempt fails auth → server routes it to
   `forward_to_cover` → opens a fresh TCP connection to the cover
   upstream.
3. If the cover upstream is on the slow side of a CGNAT or
   cloud-LB path that silently drops idle TCP bindings (typical
   2-30 min reap), the cover-server socket goes half-open
   unnoticed.
4. The 120 s `FORWARD_IDLE_TIMEOUT` outer guard fires eventually,
   but until then the server is holding open one cover-upstream
   FD + one bidirectional copy task PER junk attempt.

Effective amplification: every junk handshake the attacker spends
1 connection on costs the server 1 FD × up to 120 s. At 1000
attempts/sec sustained, that's ~120k open FDs at steady state.
On a small VPS with `ulimit -n 65535` (the iter-67 nofile audit
target), the server hits FD exhaustion AND the systemd cgroup's
`TasksMax=8192` (set in `proteus-server.service` per iter
hardening) BEFORE its own anti-DoS detectors can react.

Iter-137 wires the existing iter-28
`socket_opts::apply_dial_socket_opts_with_user_timeout` helper
into the cover-dial path: 30 s keepalive + 120 s
`TCP_USER_TIMEOUT` (Linux-only). The cover-upstream socket now:

- Sends keepalive probes after 30 s idle so a wedged peer is
  detected within ~60 s (not the kernel's default 2-hour timer).
- On Linux, gets force-closed after 120 s of unacked writes if
  the cover-upstream peer goes silent during an active forward.

Both align to the same defaults the iter-28 client-to-VPS dial
and the iter-14 server upstream-relay dial already use, so the
operator-visible socket-options story is uniform across all
three dial-stage call sites.

New test `forward_to_cover_dial_succeeds_against_loopback_listener`
exercises the dial-stage path end-to-end against a loopback
listener; the underlying socket-option helper already has its own
unit tests in `socket_opts::tests`. All 446 α unit tests + the
full workspace test suite pass. clippy clean. fmt clean.

### Security — handshake replay window: FIFO eviction policy (iter-136)

**Real security defect, retroactively classified as a low-severity
DoS-with-replay-amplification class.**

The reference replay-window implementation
(`proteus-handshake::replay::ReplayWindow`) stored
`(client_nonce, timestamp)` pairs in a `BTreeSet`. On capacity
overflow it called `seen.iter().next()` and removed the
lexicographically-smallest entry. That eviction policy is
exploitable:

1. Attacker captures a legitimate ClientHello on the wire.
2. Attacker waits for the legitimate handshake to complete and
   land in the server's replay window.
3. Attacker submits handshake attempts with attacker-chosen
   nonces that sort BELOW the captured legitimate nonce (e.g.
   `[0x00; 16]`, `[0x00; 16] | i.to_be_bytes()`, etc.). Each
   submission needs only to pass the timestamp window (90 s) —
   it fails the ML-KEM decap or the auth_tag check immediately
   AFTER, but the replay-window check fires BEFORE those, so
   even invalid attempts land in the set.
4. Once `REFERENCE_SET_CAPACITY` (65536) low-sorting nonces
   are seeded, the next insertion evicts an entry — but since
   `BTreeSet` picks the lex-smallest, the legitimate captured
   record (with its naturally-distributed nonce) gets evicted
   ahead of the attacker-controlled low-nonce flood.
5. Attacker replays the captured ClientHello. The replay
   window has forgotten it → `Verdict::Accept` → the server
   pays full ML-KEM cost AND, if the handshake was captured
   close enough to its original timestamp to still pass the
   90 s window, the server re-runs the handshake and the
   attacker gets a fresh authenticated session under the
   victim's `client_id` (no — auth still requires the
   victim's Ed25519 sig over a fresh transcript; but the
   replay arm of the defense is broken).

Mitigating factors that kept this from being P0:

- The per-IP `RateLimiter` (`rate_limit.rs`) caps the rate of
  attempts a single attacker can submit, throttling the flood
  to well below the time-to-rotate the cap.
- The 90 s `TIMESTAMP_WINDOW_SECS` bounds the replay validity
  window — an attacker who captures a record and floods the
  cap typically can't do it within 90 s on a small VPS.
- The captured ClientHello also requires the attacker to be
  on-path between the client and the server at the moment of
  capture, since the X25519 outer + TLS-1.3 outer encrypt
  the inner Proteus handshake. A pure observer cannot
  capture the inner bytes.

Even so, the eviction policy was wrong on principle: an
attacker should not be able to influence which entries get
evicted via attacker-chosen key material.

**Fix**: switch from `BTreeSet` + lex-eviction to
`HashSet` + `VecDeque` insertion-order FIFO. New entries
push to the tail; on overflow we pop the head. An attacker
cannot evict any record that landed AFTER theirs. To evict
a captured record, the attacker would need to submit
`capacity` MORE handshakes AFTER the capture — at which
point both the per-IP rate limiter and the wall clock
(TIMESTAMP_WINDOW_SECS) defeat them.

Two new tests in `replay.rs`:
- `fifo_eviction_protects_legitimate_record_from_low_nonce_flood`
  pins the exact pre-iter-136 attack: insert a legitimate
  record with the lex-MAX nonce, flood `capacity - 1` lower-
  sorting nonces, assert the legitimate record still fires
  `Replay`. Under the old BTreeSet code this test would
  return `Accept` (successful replay).
- `fifo_eviction_evicts_oldest_first` confirms the
  positive semantic: at `capacity + 1` inserts, the FIRST
  record is the one that gets evicted, not whichever
  happens to sort lowest.

All 43 handshake-crate tests pass + the full workspace test
suite is green. clippy clean. fmt clean.

### Changed — α receiver hot path: cursor-based rx_buf consume + scratch zeroize on drop (iter-135)

Two tightly-coupled changes on the α-profile `AlphaReceiver`,
landing in the same iteration because they share the same code
region and test setup:

**1. Cursor-based `rx_buf` consume (speed)**. Pre-iter-135 every
successfully-decoded frame did `self.rx_buf.drain(..consumed)`.
That's a `Vec::drain` over a leading slice, which under the hood
memmoves the unconsumed tail to position 0 — O(N) per record where
N = the remaining buffer length. At `pad_quantum=1280` a single
16 KiB TCP read holds ~12 cells; the prior code paid 12 memmoves
per syscall, each shifting up to ~16 KiB. The total memmove cost
per syscall was `O(reads_per_syscall²)` in the limit.

Post-iter-135 the receiver advances an internal `rx_offset`
cursor and only compacts the buffer when the cursor crosses
`RX_COMPACT_THRESHOLD = 64 KiB`. On bulk download that means
~1 compaction per ~50 records instead of 1 drain per record —
a ~50× reduction in tail-memmove work along the hot path.
Worst-case wasted-head memory is bounded at 64 KiB (whenever
the cursor crosses the threshold, we compact).

The `decode_frame` call now operates on `&rx_buf[rx_offset..]`
so the cursor offset is invisible to the wire decoder. The
hard-cap check also switches to measuring LIVE bytes
(`rx_buf.len() - rx_offset`) so an attacker can't bypass the
16 MiB cap by exploiting the deferred compaction.

**2. Scratch-buffer zeroize on drop (security)**. The reused
hot-path scratch buffers (`rx_aead_scratch` on the receiver,
`tx_aead_scratch` / `tx_hdr_scratch` on the sender) held the
most-recent plaintext / ciphertext between calls. The
free-function `aead::open` path already returns a
`Plaintext` wrapper that zeroizes on drop, but the optimized
in-place `AeadKey::open_in_place` writes the plaintext into a
caller-owned `Vec<u8>` that survives until the next clear.
That meant a session that ended mid-record (panic, idle
timeout, abrupt drop) left the last plaintext sitting in the
`Vec`'s allocated bytes until the allocator reused them.

Iter-135 adds explicit `zeroize()` of all three scratch buffers
in the `Drop` impls of `AlphaSender` (new) and `AlphaReceiver`
(extended). Same defense-in-depth principle as the existing
`rx_buf` / `pending` / `last_close_reason` scrubs that already
landed on `AlphaReceiver`.

3 new tests pin both halves:
- `rx_cursor_defers_compaction_below_threshold`: 5 small frames
  in one read leave `rx_offset = wire_len` AND `rx_buf.len() =
  wire_len` (cursor advanced, but no memmove fired).
- `rx_cursor_compacts_when_threshold_crossed`: 11 × 6 KiB
  frames (~67 KiB) trigger compaction; post-read cursor is
  small + `rx_buf.len() == rx_offset` (no live bytes pending).
- `rx_aead_scratch_zeroize_on_drop_does_not_panic`: smoke-test
  that the Drop impl runs cleanly even when scratch is
  non-empty.

All 445 α unit tests + 35+ integration tests still pass. No
wire-format change; sender side is untouched.

### Added — `proteus-bench alpha` / `alpha-server-tls` / `alpha-client-tls` (iter-134)

Pre-iter-134 `proteus-bench` only exposed the β (QUIC) carrier;
operators asking the **decision-grade** question — "is α (TCP +
TLS 1.3) faster than my current VLESS+REALITY setup on this VPS?"
— had no reproducible same-tool number. The α throughput-smoke
test in `proteus-transport-alpha/tests` produces a number but is
locked to raw-TCP (no outer TLS), so even running it manually
doesn't answer the production-shape question.

Iter-134 closes the gap with three new subcommands sharing the
β bench's identity-banner protocol so operators with muscle
memory for `bench beta-server` / `beta-client` get the same
shape for α:

- **`proteus-bench alpha [--tls]`**: same-host α bench. Default
  is `raw-tcp` (mirrors the in-tree throughput_smoke test —
  closest direct comparison to a regression-floor number);
  `--tls` runs the **production-shape** variant (TLS 1.3 +
  ALPN h2/http/1.1 + RFC 5705 channel binding mixed into the
  inner Finished MAC). Operators making real upgrade
  decisions read the `--tls` number, not raw-tcp.
- **`proteus-bench alpha-server-tls`**: cross-host α-TLS
  bench server. Binds + echoes + prints the same 5-line
  `BENCH_SERVER_*_HEX=` identity banner as `beta-server` plus
  the leaf cert hex for client-side pinning.
- **`proteus-bench alpha-client-tls`**: cross-host α-TLS
  bench client. Consumes the banner via `--server-*-hex`
  flags. Same `pq_fingerprint` copy-paste-typo guard as the
  β client — a mismatched fingerprint fails with a clear
  "supplied X vs computed Y" message at the boundary instead
  of an opaque "α handshake failed" 30s later.

Loopback baseline (Apple Silicon M-series, 16 MiB payload,
release):
- α raw-TCP: ~244 MiB/s (~2.05 Gbps)
- α-TLS:     ~212-248 MiB/s (~1.78-2.08 Gbps)
- β QUIC:    ~40-52 MiB/s (~0.34-0.44 Gbps)

The α-TLS number is the headline for operators choosing
between Proteus α and VLESS+REALITY — same TCP+TLS 1.3
substrate, same loopback machine, head-to-head reproducible.

Code: a new `crate::beta::blast_drain_concurrent_once` was
factored out alongside the existing `blast_drain_once` because
α (raw TCP / TLS) deadlocks under sequential blast-then-drain
when the kernel sndbuf fills (the local client task isn't
servicing the echo) — the concurrent variant runs send + recv
as joined futures on the same task. β stays on the sequential
variant because quinn's per-stream send window (64 MiB default)
buffers the whole multi-MiB payload internally.

Test coverage: 3 new unit tests pin the path (raw-TCP runs,
TLS runs, pq_fingerprint mismatch is rejected with both
fingerprints in the error). Workspace test count goes from
1683 → 1686 passing.

Two stale doc-comments in `proteus-bench/src/main.rs` and
`proteus-bench/src/beta.rs` claimed the cross-host bench
identity export was "not yet wired / next iteration"; those
already-landed and the comments were misleading future
operators reading the source. Rewritten to describe the
shipped behaviour. The `proteus-bench/src/lib.rs` "α NOT
wired" line is now updated to describe iter-134's two
variants.

### Changed — deploy/server.example.yaml ships `probe_anomaly` enabled by default (iter-133)

Pre-iter-133 the `probe_anomaly:` stanza in
`deploy/server.example.yaml` was commented out. Operators
copy-pasting the example then deploying with `cover_endpoint:`
set would see the validate WARN ("cover endpoint is configured
but probe_anomaly is unset — cover-forward bursts will not
surface as alerts"), but if they ignored the WARN (operators
do, even after iter-122's mandatory preflight gate makes them
hard to ignore), every cover-forward storm — including real
attack attempts — would go to /dev/null.

Iter-133 ships the example with `probe_anomaly:` enabled by
default. Safe-for-production settings:
`autodeny_minutes: 0` (ALERT-ONLY, no automatic blackhole until
the operator has watched the alerts for a week + confirmed no
false positives on their specific deploy), `window_secs: 300`
(5 min sliding), `threshold: 8` cover-forwards per /24,
`max_prefixes: 16384` (~1 MiB bookkeeping cap),
`autodeny_max_entries: 4096` (~128 KiB deny-list cap).

The validate WARN about `autodeny_minutes = 0` still fires —
that's intentional, it tells the operator the next step on the
deploy maturity curve ("now watch for a week then bump
autodeny_minutes to 15-60"). The DEFAULT pre-iter-133 left
operators with no probe-burst signal at all; post-iter-133 they
get the signal AND a guided next step.

### Fixed — `proteus-client validate` rejected the canonical `--config` form (iter-132)

The iter-122 deploy/README.md mandatory preflight gate calls
`proteus-client validate --config ~/.proteus/client.yaml` — same
shape as the server side. Pre-iter-132 the client took ONLY a
positional `<path>` argument (`proteus-client validate <path>`),
so the gate command failed at clap with exit 2 + "unexpected
argument '--config'". The deploy README's flagship preflight
recipe was silently broken for every operator who copy-pasted
it. Same impact class as iter-123 (phantom subcommand), but on
the per-subcommand flag-shape axis.

The iter-123 executable-contract test missed this because it
only invoked `--help` on each subcommand chain — `--help` short-
circuits clap's per-subcommand flag parser, so a subcommand can
ship with broken arg shapes and still pass the help-only check.
Iter-132 fixes both halves:

- **Client CLI**: `validate` now accepts EITHER `--config <path>`
  (mirroring the server side) OR a positional `<path>`
  (backward-compat with pre-iter-132 scripts). `conflicts_with`
  prevents using both simultaneously. No-arg invocation produces
  exit 2 + an actionable error naming both supported forms.
- **Stronger backstop**: new
  `iter132_validate_dash_dash_config_works_on_both_binaries` test
  in `deploy_readme_commands_actually_exist.rs` directly invokes
  `validate --config /tmp/does-not-exist.yaml` on BOTH binaries
  and asserts neither exits with 2 (clap rejected). 5 narrower
  tests in `crates/proteus-client/tests/iter132_validate_config_flag_symmetry.rs`
  pin each form individually + the canonical preflight-gate
  recipe exact-match form.

This closes a documentation-gap class the iter-123 surface-level
contract couldn't catch — the contract now verifies not just
"does the subcommand exist?" but also "does the documented flag
shape parse?".

### Added — Key rotation runbooks for the iter-130 anti-clobber behavior (iter-131)

Iter-130 made all key-emitting CLIs refuse to overwrite by default,
but without a corresponding section in `deploy/README.md` an
operator who re-runs the bootstrap script (or any operator who
WANTS to deliberately rotate) hits an unexplained "refusing to
overwrite" error with no clear next step.

Iter-131 adds a "Key rotation (anti-clobber by default; `--force`
to opt in)" section to `deploy/README.md` with FOUR distinct
runbooks — one per key class — because each has a different
blast radius and rotation procedure:

- **TLS cert** (`gencert --force` or just Let's Encrypt deploy
  hook): zero-downtime via the iter-129-era SIGHUP hot-reload.
- **knock PSK** (`knock-keygen --force` with staging recipe):
  must pre-distribute to every client out-of-band before cutover
  or every client fails the knock + sees only the cover-site
  response.
- **Long-term server identity** (`keygen --force` with mv-staging
  recipe): the most disruptive — every client's
  `server.pq.fingerprint` pin must be re-distributed before
  reconnect. Includes the keys-OLD/ recovery-insurance pattern
  so a botched rotation has an escape hatch.
- **Client identity** (`client keygen --force` with mv-staging
  recipe): coordinated with the server admin to add the new
  public key to the allowlist BEFORE the client cuts over (else
  "unknown client_id" with no way back).

A new contract test
(`iter131_readme_documents_key_rotation_runbooks`) pins the
section heading + all 4 runbook subsections + the `--force` flag
documentation + the pre-distribute requirement; so a future
refactor can't drop any of the runbooks without breaking CI.
The executable-contract test
(`iter123_every_readme_command_is_recognized_by_clap`) also
re-validates every command line in the new bash blocks — proving
that the operator-visible recipes actually parse, not just look
nice in markdown.

### Fixed — every key-emitting CLI silently clobbered existing files (iter-130)

Pre-iter-130 the four key-emitting subcommands (`proteus-server
keygen` / `gencert` / `knock-keygen`, `proteus-client keygen`)
silently overwrote whatever was at the target path:

- **`knock-keygen` was the worst**: it took a single `--out
  <file>` and silently replaced any file at that path with a
  32-byte PSK + mode 0600 lockdown. An operator fat-fingering
  `--out /etc/passwd` would have a real disaster on their hands
  (file replaced + locked to mode 0600).
- **`keygen`** could half-clobber a production server identity
  bundle (regenerating `server_lt.mlkem768.pk` would make the
  new fingerprint mismatch every client's `server.pq.fingerprint`
  pin → "fingerprint mismatch" on the very next connect).
- **`gencert`** would silently replace `fullchain.pem` and
  `privkey.pem`, breaking every in-flight TLS handshake AND every
  new one (if the rotation failed mid-write, the cert and key
  would be cryptographically unrelated).
- **Client `keygen`** would silently overwrite the long-term
  client identity; the new `client.ed25519.pk` would not be on
  the server allowlist → every handshake fails with "unknown
  client_id" and the operator has no way back to the old
  identity (the SK is gone).

Iter-130 makes every key-emitting subcommand **refuse to
overwrite by default**. New `--force` flag on each command opts
into deliberate rotation. Refusal returns exit 1 + an actionable
error message explaining:
1. WHAT will break if the overwrite proceeds (so the operator
   understands the blast radius before re-running with `--force`),
2. HOW to actually rotate safely (pre-distribute new key
   out-of-band → re-run with `--force` → cycle the server),
3. The alternative ("pick a different `--out` directory or
   remove the file first").

Belt-and-braces: each module exposes both `run()` (no-force,
stable lib surface) and `run_with_force(force: bool)` so future
callers can't bypass the gate by going around `main.rs`. Atomic
guarantee: rejected calls touch NO files — verified by an
integration test that captures the existing file's bytes before
the refused call and asserts byte-for-byte equality after.
gencert specifically refuses if EITHER `fullchain.pem` OR
`privkey.pem` exists (the pair must be replaced atomically; a
single-side overwrite would leave the cert and key
cryptographically unrelated).

9 new integration tests (7 server + 2 client). All existing
keygen / gencert / knock-keygen tests still pass (they use
fresh tmpdirs).

### Fixed — `proteus-server gencert` minted broken certs from any garbage SAN string (iter-129)

Pre-iter-129 `proteus-server gencert --dns-name <anything>` silently
produced a "successful" cert with whatever string the operator typed
embedded as the SAN. rcgen has no syntactic validation — it accepted
empty string, "...", "Hello World", "vps.example..com" (double-dot
typo), "internal_vps.example.com" (underscore), "-leading.example.com"
(leading hyphen), `*.` (bare wildcard), 65535-char strings — all
emitted "✓ TLS cert written" and exited 0.

The operator's first hint of trouble was rustls's opaque
`NotValidForName` error on every subsequent client handshake — with
no indication that the cert itself was the problem (vs. clock skew,
SNI mismatch, hostname pin failure, etc.). This is one of the most
operationally painful first-deploy traps: hours of debugging "why
does TLS fail?" with all the symptoms pointing at the wrong layer.

Iter-129 adds `validate_dns_name()` enforcing RFC 1035 §2.3.1 LDH +
RFC 6125 §6.4.3 wildcard semantics + RFC 1035 §3.1 label length
caps. The CLI dispatcher calls the validator BEFORE rcgen so an
operator error produces exit 2 + an actionable stderr message
naming the specific failure class ("contains an empty label", "has
a leading or trailing dot", "contains non-LDH character ' '")
PLUS the consequence ("every TLS client rejects this cert with
NotValidForName"). IP literals + wildcards remain accepted; the
gate is purely about rejecting garbage that rcgen would have
silently embedded.

Belt-and-braces: `gencert::run()` also calls `validate_dns_name()`
so any future caller (test, scripting hook) can't bypass the gate
by going around `main.rs`. Rejected calls do NOT write files —
verified by an integration test that asserts the outdir is empty
after a rejected call. 15 unit tests + 9 integration tests.

### Fixed — `proteus-bench soak --min-success-rate` accepted impossible values (iter-128)

Pre-iter-128 `proteus-bench soak --min-success-rate 2.5` made every
soak fail (no real success rate can exceed 1.0), but the error message
("soak FAILED: success_rate 1.0000 < min 2.5000 OR spawn_leak=0 OR
zero dials succeeded") read like a real regression. The most
operationally dangerous shape: a CI script fat-fingering `0.99` to
`2.99` would have every commit produce a misleading "regression"
error.

The silent-fail variant was worse: `--min-success-rate NaN` is
silently accepted, then `passed(NaN)` returns false unconditionally
(IEEE-754 NaN comparisons all return false). Every soak failed
silently with no hint why.

Iter-128 adds `reject_invalid_success_rate()` gating the value to a
finite fraction in [0.0, 1.0]. 0.0 is valid (explicit operator
intent of "don't gate on success rate, only on spawn_leak +
zero-dials") and 1.0 is valid (strictest zero-regression-tolerance
gate). Both boundary tests pin those. Error message states
"fraction, NOT a percentage" so an operator who typed `99` instead
of `0.99` understands the unit.

6 new iter-128 tests; 30 total in the bench arg-validation file.

### Fixed — `proteus-bench` accepted unphysical MTU + loss-pct values (iter-127)

Pre-iter-127, even after the iter-126 zero-arg gate, the bench
still accepted unphysical MTU and loss-percentage values:

- `--initial-mtu 12` → quinn-proto silently clamps to its internal
  ~1200 floor; bench emits a JSON report with `mtu_init=12` echoed
  back while running at 1200. Operator never learns the bench ran
  at a different MTU than they asked for.
- `--initial-mtu 65535` → same silent clamp behavior on the high side.
- `--mtu-upper-bound 0` → upper-bound knob becomes a no-op; PMTU
  probing can't go anywhere.
- `--mtu-upper-bound 1300 --initial-mtu 1400` → ceiling below floor;
  same silent no-op.
- `--loss-pct 150.0` → bench runs with 100% loss, dies 5s later
  with misleading "handshake timed out" message.
- `--loss-pct -5.0` → bench runs with negative loss (mathematically
  meaningless).
- `--loss-pct NaN` → undefined behavior in netem forwarder math.

Iter-127 adds `reject_out_of_range_mtu()` (range [1200, 9000] = RFC
9000 §14 floor + jumbo-frame ceiling) and `reject_invalid_loss_pct()`
(finite, [0.0, 100.0]) plus a coherence check that
`--mtu-upper-bound ≥ --initial-mtu`. Boundary values that ARE
valid (`--loss-pct 0` = passthrough, `--loss-pct 100` = chaos test)
pass the gate — explicit boundary tests pin both. 10 new iter-127
tests in `tests/iter126_zero_arg_rejection.rs`.

### Fixed — `proteus-bench` accepted zero-valued args, ran through, then failed mysteriously (iter-126)

Pre-iter-126 `proteus-bench beta --connect-timeout-secs 0` ran
through bench setup and then died with the cryptic
`Error: Connect("handshake timed out after 0ns")`. Same trap on
`--total-timeout-secs 0` (instant abort), `--runs 0` (silent zero-
iteration loop), `--payload-mib 0` (degenerate empty report),
`--chunk-kib 0` (div-by-zero risk in per-record accounting),
`--clients 0` (no-op soak summary), `--users 0` (round-robin
panic), `--duration-secs 0` (empty soak summary).

This is operationally dangerous because bench scripts get plumbed
into CI gates: `proteus-bench soak --min-success-rate 0.99 ...` is
the standard "did this commit regress?" check. A soak with
`--duration-secs 0` would exit 0 with an empty summary, silently
passing the gate while measuring nothing.

Iter-126 adds a unified `validate_*_args()` pass that runs BEFORE
any bench setup. Every numeric arg that must be positive is gated
at parse time with exit 2 + a clean stderr message naming the bad
flag AND explaining WHY zero is wrong (so the operator who tried
`--foo 0` understands and doesn't just retry with a different
bad value). Symmetric with iter-108/109/110/111/117 on the other
binaries.

Covered subcommands: `beta` (5 args), `soak` (6 args),
`beta-client` (5 args). `beta-server` has no positive-required
numeric args. 14 new integration tests in
`tests/iter126_zero_arg_rejection.rs` pin every gate; the final
test exercises the positive-arg happy path so the gate can't
regress to "reject everything".

### Fixed — `check-host` silently emitted PASS for audits it didn't run (iter-125)

Pre-iter-125 `proteus-server preflight check-host` and
`proteus-client check-host` emitted **PASS** for every audit they
skipped because the operator hadn't passed `--config`. The summary
line said "0 fail" and the careless operator concluded their host
was safe — but on the server side the key-file mode audit (the #1
long-term-key exfil class) had been silently skipped, and on the
client side ALL FOUR config-derived checks (client SK mode,
server_endpoint DNS resolvability, bootstrap_dns DoH-leak surface,
trusted_ca PEM readability) had been silently skipped.

Each of those four client-side checks is the **sole audit on its
respective class** — a silent skip = a class-wide blind spot.
Server-side, world-readable `*_sk` files are catastrophic on
shared/multi-user hosts.

Iter-125 makes every skipped-because-no-config check a **WARN**
with an `AUDIT SKIPPED` message in shout-case. The operator sees
"1 warn" (server) or "4 warn" (client) in the summary, the message
states explicitly what was NOT verified + how to re-run with the
audit enabled. Exit code stays 0 (WARN is non-fatal) so the
dev-laptop "I just want to see my own host's posture" workflow
keeps working — but the dishonest "everything green" outcome is
gone. New tests in both `host_preflight.rs` modules pin the WARN
semantics so a future refactor can't silently regress.

### Fixed — `deploy/README.md` documented non-existent subcommands (iter-123)

Pre-iter-123 the deploy guide's mandatory preflight gate
(iter-122) instructed operators to run
`proteus-server host-preflight` and `proteus-client host-preflight`
— neither subcommand exists. The real CLI shape is
`proteus-server preflight check-host` (under the `preflight`
umbrella, alongside `check-ip-reputation` + `all`) and
`proteus-client check-host` (top-level, no umbrella). An operator
following the gate would have hit clap exit 2 with
"unrecognized subcommand 'host-preflight'" on step 2 of 5.

Root cause was a missing executability assertion: the
iter-118/120/122 README contract tests only grepped the README
for the string `proteus-server host-preflight`, which passed
trivially because the README contained the string — they couldn't
distinguish aspiration from reality.

Iter-123 fixes both halves:

- **README**: rewrites the host-posture preflight section + the
  5-command gate + the security-checklist gate to use the real
  command names. Adds an explicit "asymmetric subcommand naming"
  paragraph (server `preflight check-host` vs. client `check-host`)
  so operators who skim and grep for "host-preflight" get a
  signpost instead of clap exit 2.
- **Source comments**: server `validate.rs` + client `validate.rs`
  warn messages were pointing operators at the same phantom
  command. All operator-facing warn text now references the real
  subcommand names.
- **CHANGELOG**: prior entries referencing the phantom commands
  rewritten to the real names (history of "what we shipped" must
  match what actually shipped).
- **New backstop**:
  `crates/proteus-server/tests/deploy_readme_commands_actually_exist.rs`
  parses every fenced bash block in `deploy/README.md`, extracts
  every `proteus-{server,client} <subcommand chain>`, and shells
  out to the actual binary with `--help` on each. Any documented
  command clap doesn't recognise FAILs the test with the full
  list of broken invocations — string-grep tests can no longer
  pin an aspirational contract. A narrow regression test
  (`iter123_readme_does_not_reintroduce_phantom_host_preflight_subcommand`)
  pins the specific `host-preflight` phantom so a future revert
  fails CI immediately with a copy-pasteable explanation.

### Added — multi-VPS HA client (`server_endpoints:` pool)

- `EndpointPool` + per-entry `EndpointHealth` with streak-based
  suppression + capped exponential back-off (mirrors
  `CarrierHealth`'s state machine).
- YAML `server_endpoints: [primary, backup1, backup2, ...]` —
  operator-pre-configured pool dispatched in declaration order.
- SIGHUP-driven hot-reload: edit `client.yaml` and SIGHUP to swap
  in a new endpoint list without restart; per-entry counters +
  suppression state are carried over for any entry whose address
  string is preserved (`EndpointPool::new_with_carryover`).
- `proteus_client_pool_reload_{attempts,succeeded}_total` counters
  + `ReloadablePool::record_attempt_failed()` so config-parse
  failures during SIGHUP show up as a real
  `(attempts - succeeded) > 0` gap that the bundled
  `ProteusClientPoolReloadFailing` alert + `alerts-check`
  evaluator + Grafana dashboard panel all detect.
- `proteus-client connect-test --all-endpoints` exercises every
  pool entry independently (fresh DNS + TCP + handshake per
  entry, one failure does not abort the rest). Overall exit code
  is 0 IFF every entry succeeded.
- `proteus-client validate` now detects:
  - SNI consistency — pool entries with hostnames that diverge
    from `tls.server_name` (cert verification would fail at
    dispatch time); IP literals are correctly skipped.
- `proteus-client check-host` (the operator-facing CLI surface
  for the client's host-posture preflight; the internal module
  is named `host_preflight` for symmetry with the server side)
  now scans `server_endpoints:` list entries for DNS
  resolvability (pre-iter-44 only the primary `server_endpoint:`
  scalar was checked).

### Added — observability (Prometheus + alerts + dashboard pentad)

- 4 SIGHUP reload-failing alerts for the server-side reload
  surfaces (firewall, rate_limit, user_rate_limit,
  handshake_budget) with matching in-process `alerts-check`
  evaluator rules and a stacked Grafana dashboard panel
  (`id=60`) showing all four `(attempts - succeeded)` gaps.
- 3 per-endpoint pool panels on the bundled Grafana dashboard:
  per-endpoint suppression state, per-endpoint dial outcome
  rate, pool-reload backlog stat (`id=53,54,55`).
- Cover-forward observability pentad — metric +
  `ProteusCoverForwardRejecting` / `ProteusCoverForwardStorm`
  alerts + alerts-check evaluator + Grafana dashboard panels
  (`id=32,33`).
- Pool-reload-failing client-side alert
  `ProteusClientPoolReloadFailing` + in-process `alerts-check`
  evaluator.

### Fixed — observability correctness (false-positive / false-negative class)

- **Client pool SIGHUP** (iter 40): SIGHUP-with-config-parse-error
  silently no-op'd. The alert designed to catch silent edit-
  didn't-apply events literally could never fire — every
  `reload()` call incremented both attempts AND succeeded in
  lockstep. Fix: bump attempts WITHOUT bumping succeeded on
  the config-parse-failure path; gap is now a true signal.
- **Server SIGHUP per-section** (iter 41): operators who SIGHUPed
  without a `rate_limit:` / `user_rate_limit:` /
  `handshake_budget:` block saw the gap grow by 1 on every
  SIGHUP, permanently tripping the matching alerts as a false
  positive. Fix: bump succeeded on every non-parse-failure
  outcome — section-absent counts as "reload completed (no-op)".

### Added — runtime-state + per-user observability completeness (iter 101-105)

The pattern of the prior iter-98/99 arc continued: every
exposed counter / gauge that still lacked an alert + check +
dashboard surface gets one. After iter-105, the operator
running EITHER Prometheus OR the in-process `alerts-check`
sees every documented attack signal AND every operational
health metric within minutes of it changing.

- **`ProteusClientPanic`** (iter 101): mirror of server-side
  panic alert. The client emitted `proteus_panics_total` via
  the shared `proteus-panic-hook` crate but the bundled
  client alerts file + in-process check never flagged it.
  CRIT-grade at rate > 0.
- **`ProteusServerDrainStuck`** (iter 102): `proteus_ready=0
  + proteus_up=1` is the legitimate SIGTERM-drain state but
  if it sticks (in-flight sessions refusing to close OR
  supervisor never escalating to SIGKILL) the binary sits
  there indefinitely. WARN at 5 min sustained drain.
- **session-lifecycle reaps panel** (iter 103): Grafana
  panel id=100 surfaces `proteus_session_idle_reaped_total`
  + `proteus_session_byte_budget_exhausted_total`. Wedged-
  peer + per-session-cap-pressure signals operators want
  for capacity planning.
- **top-5 per-user bandwidth panel** (iter 104): Grafana
  panel id=101 uses `topk(5, rate(proteus_per_user_bytes_sent_total[1m]))`
  to show who's actually using the proxy at any moment.
  Visual abuse-by-credential spotting before the alert
  fires.
- **`ProteusUserQuotaAdmissionRejecting`** (iter 105): per-
  user `period_bytes` cap rejections. Pre-iter-105 the
  operator had no signal when a user_id consumed their
  quota; all new sessions for that user got admission-
  rejected silently. WARN @ rate > 0/sec.

### Added — config-knob sanity + attack-detection observability (iter 83-99)

The validate surface now catches **every documented
`= 0` / absurd-value foot-gun** on both server and client
config, plus closes the alert/check gap on every attack-
detection counter that was previously exposed but unalerted:

**Config-knob sanity (iter 83-89, iter 91-96)**:
  - client: max_inflight_sessions, socks_request_timeout, drain_secs,
    tcp_keepalive_secs, alpha_dial_timeout_secs, healthz_staleness_secs,
    beta_mtu_upper_bound, beta_ack_eliciting_threshold
  - server: handshake_deadline_secs, max_connections, tcp_keepalive_secs,
    user_quotas (period_secs, max_entries, override dupes/orphans),
    user_quarantine (ttl_secs, max_entries), per_user_bandwidth_rate
    (window_secs, max_users, exit_factor, threshold_mb_per_sec),
    per_user_conn_limit, abuse_detector (byte_budget + rate_limit),
    pad_quantum, drain_secs, session_idle_secs, max_session_bytes,
    startup_self_test_timeout_secs, periodic_self_test_interval_secs,
    periodic_self_test_failure_threshold, tls_cert_watcher_interval_secs,
    beta_initial_mtu/mtu_upper_bound/ack_eliciting_threshold

Each knob's three-state pattern: `=0` typically FAIL or
WARN-with-observability-only-note, absurd-value WARN,
sensible-value PASS. Operators can no longer ship a config
that silently disables safety surfaces.

**Catastrophic open-relay coherence (iter 97)**: pre-iter-97
the operator could ship `client_allowlist: []` + wildcard
`listen_alpha` + no firewall — three documented WARN signals
that COMBINE into an unauthenticated public open-relay. The
combination is now a FAIL with three documented recovery paths.

**Attack-detection observability (iter 98-99)**: 7 metrics
that existed but had no alert/check/dashboard coverage:
  - AEAD drops (active MITM tampering signal — page-grade at
    >1/sec)
  - handshake failure ratio (credential bruteforce / GFW
    probing signal)
  - firewall denials (active scanning from blocked ranges)
  - handshake budget exhausted (DDoS OR legitimate burst)
  - max_connections cap hit (FD ceiling)
  - per-user rate rejected (credential compromise)
  - user-quarantine rejected (previously-banned user)

Each gets the 4-surface pentad (validate + Prometheus alert +
in-process alerts-check + Grafana dashboard panel where
appropriate). Pre-iter-99 active MITM tampering on the data
plane was COMPLETELY invisible outside the dashboard — no
alert ever fired. Now AEAD drops > 1/sec page within 2 min.

### Added — security observability gates (iter 78-81)

Three more security-observability pentads + one runtime alert:

- **SSRF rejection dashboard panel** (iter-78): completes the
  4-surface pentad for SSRF (validate iter-75 + Prometheus
  iter-76 + alerts-check iter-76 + dashboard iter-78).
  Operators see credential-compromise + attacker-mapping-
  internal-network attempts BEFORE the alert pages.
- **Per-user abuse-fires alerts + check** (iter-79):
  three new Prometheus alerts + matching in-process
  alerts-check loop covering byte_budget / rate_limit /
  per_user_bandwidth abuse-detectors. Pre-iter-79 the metrics
  existed but no alert fired — credential-compromise +
  attacker-scripting-heavy-use was invisible.
- **Per-user abuse-fires dashboard panel** (iter-80): closes
  the visual surface for the iter-79 alerts. Three-series
  stacked timeseries lets operators see the building trend.
- **Probe-anomaly pentad** (iter-81): full 4-surface coverage
  for the per-/24 source-IP probe-anomaly detector (2 alerts +
  check + dashboard panel in one commit). Pre-iter-81 the
  metric was emitted but no alert fired directly; operators
  had to grep for the per-/24 breakdown manually after seeing
  the broader cover-storm alert.

### Added — security observability gates (iter 73-76)

Four more layers closing security blind-spots, each pairing
validate-time prevention with runtime alert/check:

- **admin_listen + metrics_listen wildcard FAIL escalation**
  (iter-73): pre-iter-73 wildcard binds on the unauthenticated
  admin/metrics endpoints were uniformly WARN. Now FAIL on
  `0.0.0.0` / `[::]` — exposing the full HA topology +
  panic_count + cert-expiry-timeline to an internet scanner is
  attack-prep material the operator should NOT ship by accident.
- **Handshake p99 latency alerts** (iter-74): the histogram
  metric existed + dashboard panel referenced it, but no alert
  fired on creep. CPU-exhaustion attacks (PoW-bypass → ML-KEM
  Decap flooding) were invisible outside the dashboard. Two
  tiers: WARN at p99>200ms (10min), CRIT at p99>1s (5min, page-
  grade). In-process alerts-check approximates via mean.
- **outbound_filter SSRF-policy validate sanity** (iter-75):
  pre-iter-75 an operator could ship `disabled: true` or
  `replace_default_blocklist: true` and validate said green.
  Now FAIL on the three foot-guns: explicit-disable (any
  allowlist'd client → LAN/IAM-creds), blanket-blocklist-
  replace (almost always a typo), and unparseable CIDR
  (runtime silently ignores; gate breaks).
- **SSRF-attempts runtime alerts** (iter-76): the
  `proteus_outbound_blocked_total` counter existed but no
  alert fired. Credential compromise + attacker mapping
  internal network via proxy was visible only via manual
  access_log audit. Two tiers: WARN rate>0 (5min), CRIT
  rate>1/sec (2min, page-grade). In-process alerts-check
  uses cumulative-counter heuristics.

### Added — client-side validate security gates (iter 70-71)

Two more validate-time security gates closing client-side
operator-trap classes:

- **bootstrap_dns.direct_ip private-IP detection** (iter-70):
  WARN on RFC 1918 / CGNAT / link-local / ULA / cloud-metadata
  IP pinned for client DNS. Three trap classes called out:
  (a) "VPS is actually a LAN box" paste error, (b) cloud
  metadata IP `169.254.169.254` leaks user_id + Ed25519 sig
  into the metadata service logs, (c) WireGuard-tunneled
  setups legitimately use this — flagging is the right default
  but stays WARN-not-FAIL for the legitimate case.
- **socks_listen open-proxy detection** (iter-71): SOCKS5
  inbound has NO authentication (RFC 1928 method 0x00). FAIL
  on wildcard binds (`0.0.0.0`, `[::]`) which on a cloud VPS
  make the entire internet a free relay through the operator's
  egress IP. WARN on any other non-loopback bind (deliberate
  tunnel-interface sharing — flag the trust assumption).

### Added — validate-time security gates (iter 65-68)

Four new preflight checks targeting silent security/privacy
failures that pass all earlier validate gates:

- **metrics_token strength** (iter-65): WARN on <32 char tokens
  (brute-forceable), FAIL on case-insensitive trivial blacklist
  (`changeme` / `token` / `admin` / `password` / etc. — the first
  values any scanner tries), WARN on world-readable mode.
  Bearer token is the ONLY auth gate on non-loopback /metrics.
- **max_cover_forwards bound** (iter-66): FAIL on explicit `0`
  (unbounded; FD exhaustion under probe storm), WARN when both
  `max_cover_forwards` and `max_connections` are unset.
  Mirrors the existing runtime warn at preflight time.
- **cover_endpoint in private IP space** (iter-67): FAIL on
  RFC 1918 / RFC 6598 CGNAT / RFC 4193 ULA / link-local. Catches
  the LAN-exposure trap (internal mgmt UI exposure) AND the
  cloud-metadata foot-gun (`169.254.169.254` exfils IAM creds
  on AWS / GCP / Azure / DO).
- **cover_endpoints[] pool private-IP check** (iter-68): sister
  fix applying iter-67 to every pool entry. The pool has the
  same exposure as single-URL cover.

### Added — speed (Hy2 / TUIC5-grade data plane) iter 61-63

Three data-plane speed wins closing the remaining gap with
Hy2 / TUIC5 single-stream throughput on long-fat-pipe paths:

- **UDP socket buffer tuning to 7 MiB** (`SO_RCVBUF` +
  `SO_SNDBUF`). Linux's `net.core.rmem_default` ≈ 212 KiB
  capped β single-stream throughput well below Hy2 / TUIC5;
  matching their 7 MiB target sustains 1 Gbit/s at ~500 ms
  RTT. Wired at all 3 β socket bind sites (server, client
  initial dial, client migration rebind). Best-effort: kernel
  clamps above `net.core.rmem_max` are warn-logged with the
  exact sysctl command operators run to raise the cap.
- **BufWriter on the server-upstream relay leg**. Pre-iter-62
  every inbound Proteus record became its own TCP write
  syscall to the upstream server. 64 KiB BufWriter with
  adaptive flush (flush on < capacity, coalesce at capacity)
  collapses small-frame workloads (HTTP/2 control, gRPC) to
  one syscall per batch boundary.
- **BufWriter on the client-downstream SOCKS5 leg**. Sister
  fix for the symmetric trap on the OTHER side of the relay
  — pre-iter-63 every inbound Proteus record became its own
  TCP write syscall to the local SOCKS5 client.

Combined effect: with iter-61's UDP buffer headroom and
iter-62/63's syscall-coalescing, the data-plane bottleneck
shifts back to crypto throughput (AEAD seal+open) which the
α profile already amortizes via 64 KiB BufWriter and the β
profile via QUIC's stream send-buffer.

### Added — validate-time operator-trap detection (iter 46-57)

Eleven new preflight checks in `proteus-server validate` /
`proteus-client validate`, every one catching a class of
silent-failure-at-deploy-time that was previously missed:

- **Server TLS cert-expiry** — EXPIRED leaf cert → FAIL,
  <14 days → WARN, otherwise PASS (matches the runtime
  `ProteusTlsCertExpired` / `ProteusTlsCertExpiringSoon`
  alerts; previously these only fired AFTER deploy).
- **Client trusted_ca cert-expiry** — same three-state policy
  for `tls.trusted_ca` pinning bundles. Multi-CA bundles
  report the EARLIEST notAfter (any expiring entry is the
  actionable signal).
- **β cert-expiry on split α/β paths** — `beta_cert_chain` +
  `beta_private_key` get expiry coverage independent of α
  when explicitly split.
- **All-zero key/pubkey sentinel** — `keys.*` and
  `client_allowlist[*].ed25519_pk` files with uniformly-zero
  content → FAIL (catastrophic security failure: secret keys
  become trivially-forgeable identities; allowlist pubkeys
  auth-pass any client presenting the zero key).
- **access_log + 3 other runtime-written paths probed for
  write permission** — operator's `/var/log/proteus` exists
  but is owned by root:root mode 0700 while proteus runs as
  proteus:proteus → previously validate said green, binary
  exited at startup. Now FAIL with `chown -R` recovery hint.
  Covers `access_log`, `restart_state_file`,
  `user_quotas.persistence_path`,
  `user_quarantine.persistence_path`.
- **knock_psk_file parse check** — runs the same
  `knock_keygen::load()` the binary uses at startup, surfaces
  the same diagnostic at preflight (was fatal-at-startup).
- **Secret-key file mode warn** — Unix mode bits on `*_sk`
  files; group-or-other-readable → WARN with `chmod 0600`
  hint (`preflight check-host` is the FAIL gate for the same
  class; validate is early-warning).
- **Pool ↔ tls.server_name SNI consistency** — pool entries
  with hostnames diverging from `tls.server_name` → WARN
  (cert verification would fail at dispatch with no obvious
  cause). IP literals are correctly skipped (operator
  deliberately decoupled routing-address from cert-identity).
- **user_id whitespace + non-ASCII** — YAML-quoted
  `user_id: "alice "` becomes byte-string "alice " (6 bytes);
  server allowlist's `user_id: alice` (5 bytes) never matches
  → FAIL with unquote-or-strip hint. Non-ASCII → WARN
  (paste-not-retype reminder).
- **Allowlist duplicate user_id** — `client_allowlist`
  with two `alice` entries → FAIL with both indices. The
  runtime `.find()` returns the FIRST match; the second
  entry is dead code (key-rotation gone backwards trap).

### Added — stability hardening

- `panic = "unwind"` workspace release profile (replaces
  pre-iter-24 `panic = "abort"`) so a panic in one tokio spawned
  task no longer tears down the whole binary. Pinned by tests
  on both server + client + workspace `Cargo.toml`.
- TCP_USER_TIMEOUT (Linux-only) on outbound client dials — catches
  DEAD ACTIVE peers that go silent mid-stream within ~120 s
  instead of waiting for the kernel's ~15-minute retransmit
  deadline.
- TCP keepalive on every outbound dial — closes the silent-NAT-
  death class for long-idle Proteus sessions.
- EMFILE / ENFILE / ENOMEM survival in every accept loop (4
  server + 1 client SOCKS5 + 1 metrics-http + 1 admin) — the
  loop now distinguishes transient kernel errors (backoff + retry)
  from fatal listener-dead errors (clean exit + supervisor
  restart).
- Cover-forward concurrency cap (semaphore) so a probe storm
  cannot exhaust FDs by spinning up unbounded cover-tunnel
  tasks.
- Poisoned-lock recovery on `ReloadableAcceptor` + `ReloadablePool`
  — a panic mid-write no longer makes the next read a CRIT.
- SOCKS5 RFC 1928 §6 REP codes (0x03/0x04/0x05/0x06) on upstream
  dial failure — pre-iter-29 every failure showed up as
  generic "could not connect to proxy" to the browser/curl
  downstream.
- Log throttling on per-CONNECT × per-entry pool-failure spam.

### Added — speed (data-plane micro-optimisations)

- Per-CONNECT startup-cached `TlsConnector` + `HandshakeConfigSource`
  + `BetaClientCrypto` — eliminates per-CONNECT disk reads +
  crypto setup.
- Adaptive flush + 64 KiB read buffer on relay pumps.
- ChaCha20-Poly1305 cipher cached + scratch reused in α data plane.

### Documentation

- systemd units document the `RUST_PANIC_ABORT=1` opt-in for
  operators who prefer systemd-restart-on-panic over keep-
  running semantics.

## [0.1.0] — 2026-05-16

First production-deployable milestone (M1). Ships the α-profile (TLS 1.3
over TCP) with the full handshake / ratchet / cover-forward / DoS-defense
surface.

### Added — protocol

- α-profile wire format (spec §4) — byte-exact `ProteusAuthExtension`
  encoder/decoder, inner-packet framing, QUIC varint per RFC 9000 §16.
- Hybrid post-quantum KEX — X25519 + ML-KEM-768 concatenation hybrid
  per draft-ietf-tls-hybrid-design-11.
- TLS 1.3-style key schedule with HKDF labels (`derived`,
  `c hs traffic`, `s hs traffic`, `c ap traffic`, `s ap traffic`,
  `exp master`, `res master`).
- Mutual-auth Finished MACs (HMAC-SHA-256) over transcript hashes
  `H(CH)`, `H(CH || SH)`, `H(CH || SH || SF)`, `H(CH || SH || SF || CF)`.
- AEAD record layer (ChaCha20-Poly1305) with 12-byte XOR'd nonce derived
  from `(epoch:24 || seqnum:40)` per spec §4.5.2.
- Per-direction symmetric ratchet — auto-rotate AEAD key every 4 MiB or
  16 384 records via `HKDF-Expand-Label(secret, "proteus ratchet v1")`.
- `RECORD_CLOSE` (0x12) wire type with error code + reason phrase, both
  AEAD-protected under the current direction key.
- Anti-replay sliding-window over `(client_nonce, timestamp)` pairs
  with a 90-second timestamp guard.
- Anti-DoS proof-of-work (spec §8.3) — operator-tunable difficulty
  0…24 leading zero bits over `SHA-256(server_pq_fingerprint ||
  client_nonce || solution)`. Both client `pow::solve` and server
  `pow::verify` are wired.
- Cover-server pass-through on auth failure (spec §7.5) —
  byte-verbatim splice of the consumed handshake bytes plus the live
  TCP stream to a configured cover endpoint.
- Real TLS 1.3 outer wrapper (rustls + tokio-rustls + ring crypto
  provider). The Proteus handshake runs inside an
  `application_data` record stream; passive DPI sees standards-compliant
  TLS 1.3 with ALPN `h2`/`http/1.1`.

### Added — server (`proteus-server`)

- `keygen` — emits ML-KEM-768 + X25519 + PQ fingerprint, mode 0600.
- `gencert` — self-signed TLS cert + PKCS8 key for testing / quickstart;
  drop-in replaceable with Let's Encrypt `fullchain.pem` + `privkey.pem`.
- `run --config /etc/proteus/server.yaml` — production entry point.
- YAML config — `listen_alpha`, `tls`, `cover_endpoint`, `client_allowlist`,
  `metrics_listen`, `rate_limit`, `handshake_deadline_secs`,
  `tcp_keepalive_secs`, `pow_difficulty`.
- Per-IP token-bucket rate limiter with 60-second auto-vacuum.
- Slowloris-class handshake deadline (default 15 s; configurable).
- TCP keepalive on every accepted stream (default 30 s).
- `SO_REUSEADDR` listener so the service restarts immediately after
  SIGTERM without TIME_WAIT block.
- Prometheus exposition over plain HTTP at `metrics_listen` —
  10 counters: sessions_accepted, handshakes_succeeded,
  handshakes_failed, handshake_timeouts, rate_limited, cover_forwards,
  tx_bytes, rx_bytes, aead_drops, ratchets.
- Structured tracing logs with peer-address field for triage.
- SIGTERM / SIGINT graceful drain (30-second window).
- 16 MiB rx-buffer hard cap (memory DoS defense).
- 10-second upstream dial timeout in the relay path.
- systemd unit with full hardening profile (NoNewPrivileges,
  ProtectSystem=strict, SystemCallFilter, MemoryDenyWriteExecute,
  CAP_NET_BIND_SERVICE).
- Multi-stage Dockerfile + docker-compose with non-root 911:911 user.

### Added — client (`proteus-client`)

- `keygen` — emits Ed25519 identity keypair, mode 0600.
- `run --config /etc/proteus/client.yaml` — SOCKS5 inbound (RFC 1928,
  CONNECT only, no-auth) tunnelling through a Proteus α session.
- YAML config — `server_endpoint`, `socks_listen`, `user_id`, `keys`,
  `tls`, `pow_difficulty`.

### Added — testing

- 110 tests across 8 crates: spec / wire / crypto / handshake / shape /
  transport-alpha unit tests + 3 integration test files.
- Fuzz / property-style tests against every decoder
  (`auth_ext`, `inner_header`, `alpha_frame`, `varint`) over 30 000
  random byte sequences each — no panics, bounded runtime.
- End-to-end integration tests over plain TCP and TLS-wrapped TCP,
  including a 16 MiB stress test that crosses multiple ratchets.
- Production-realistic SOCKS5-via-TLS test with an upstream echo
  server, full CONNECT relay, byte-stream-aware assertions.
- Proof-of-work integration tests verifying both the
  "client solves puzzle → success" and "client skips puzzle → reject"
  paths.

### Added — CI

- `.github/workflows/ci.yml` — fmt, clippy `-D warnings`, test on Linux
  + macOS, release build with binary smoke tests (keygen / gencert
  /verifying 0600 modes), `cargo audit`, `cargo deny`.
- `deny.toml` — license allowlist, dupe-version warning, banned
  `openssl-sys` / `native-tls`.

### Security notes

This release strictly exceeds VLESS+REALITY on the following axes:

1. **Forward secrecy** — Proteus rotates AEAD keys every 4 MiB; REALITY
   keeps a single AEAD key for the whole session.
2. **Post-quantum confidentiality** — Proteus's handshake hybridizes
   X25519 with ML-KEM-768 (NIST PQC Round 4 winner); REALITY ships
   only classical X25519.
3. **Anti-DoS proof-of-work** — Proteus has an operator-tunable PoW
   gate before ML-KEM Decap; REALITY has nothing equivalent.
4. **Memory DoS hard cap** — Proteus enforces a 16 MiB per-session
   receive ceiling; REALITY relies on the underlying transport.
5. **Mechanically verifiable mutual-auth** — Finished MACs over a
   precisely-defined transcript hash chain; REALITY's authentication
   ties only to TLS-ClientHello shape and short-id.
6. **Real TLS 1.3 outer** — Proteus advertises ALPN `h2`/`http/1.1`
   like a normal HTTPS server; the entire handshake is genuine TLS,
   with the Proteus extension carried in `0xfe0d`.

### Limitations

- M1 ships only the α (TLS-over-TCP) profile. The β profile
  (multipath, UDP/QUIC outer) and γ profile (relay-pool) are M2 / M3.
- The asymmetric DH ratchet primitive exists in `proteus-crypto::ratchet`
  but is not yet wired into the data plane (M2 will wire it).
- Active shape-shifting (cover-IAT online learning) is not implemented;
  this is M3.
- Multipath QUIC binding is M4.

[0.1.0]: https://github.com/Icarus603/network-from-scratch/releases/tag/proteus-v0.1.0
