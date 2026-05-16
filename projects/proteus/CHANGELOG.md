# Changelog

All notable changes to the Proteus reference implementation.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once we hit `1.0.0`. Pre-1.0 minor bumps may include breaking changes;
patch bumps are bug-fix only.

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
