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
- `proteus-client host-preflight` now scans `server_endpoints:`
  list entries for DNS resolvability (pre-iter-44 only the
  primary `server_endpoint:` scalar was checked).

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
  hint (host-preflight is the FAIL gate for the same class;
  validate is early-warning).
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
