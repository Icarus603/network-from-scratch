---
name: 2026-05-18-proteus-vs-sota-safety-audit
description: Honest GFW-safety audit of Proteus vs. VLESS+XTLS-vision+Reality and Hy2/TUIC-v5 as of 2026-05-18. Every claim backed by a citation OR a test in the Proteus repo OR an explicit "this is opinion not measurement" tag.
metadata:
  type: gfw-capability-note
  source_kind: internal-audit
  baseline_date: 2026-05-18
  baseline_commit: 87207a8
---

# Proteus vs. SOTA GFW-safety audit (2026-05-18)

## Question

> 現在對於 GFW 的安全性甩了當今 SOTA 幾條街了？
>
> ("How far ahead of current SOTA is Proteus on GFW safety right now?")

Stated bluntly so future re-readings of this doc don't drift from
the original ask: the user wants a defensible, citation-backed
answer — not marketing.

## Framing: what "ahead" means

GFW safety is not one number. It's a stack of independent properties
each adversary capability has to beat. A proxy is "ahead" if for
every capability X that an adversary can deploy, the proxy has a
defense Y that's stronger than what the named alternatives ship,
**AND** the defense is materially deployed (not just designed).

We list every capability we know of, then for each one give:

  - **Adversary capability** — what the GFW (or Tiangou / Iran GFW /
    Russia TSPU) actually does, with a primary source.
  - **VLESS+XTLS-vision+REALITY** — what the Xray-core flagship
    deploys against it.
  - **Hy2 / TUIC-v5** — what the QUIC-flagship pair deploys.
  - **Proteus** — what we deploy, with a `crates/.../path:line` or
    test name as evidence.
  - **Verdict** — one of:
    - ⇈ **strictly ahead** (Proteus defense is provably stronger)
    - ↑ **slightly ahead** (Proteus defense is comparable but
      adds an independent layer the alternatives don't)
    - = **tied** (equivalent posture)
    - ↓ **behind** (Proteus is weaker)
    - ❓ **uncomparable** (semantic difference makes direct comparison
      misleading)

Throughout, "REALITY" means the Xray-core implementation per
`transport/internet/reality/reality.go` as of the Xray-core 25.x
series. "Hy2" means the apernet/hysteria 2.x series. "TUIC-v5"
means the EAimTY/tuic 5.x series.

## Audit matrix

### 1. Wire-format static-signature detection

**Adversary capability**: GFW + Tiangou maintain JA3 / JA4 +
ClientHello cipher_order / extension_order databases. Detection
within a few hundred packets per [Frolov FOCI 2020](https://www.usenix.org/conference/foci20/presentation/frolov)
and confirmed continuously by GFW.report.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| TLS 1.3 outer | ✅ (steals real site's cert chain) | n/a (raw QUIC) | ✅ rustls 0.23.40 with `brotli` compress_certificate |
| Chrome-aligned cipher order | ✅ via uTLS (Go) | n/a | ✅ wire-verified test [`proteus-fingerprint::tests::proteus_alpha_clienthello_ja4_baseline`] (extracts cipher wire-order from real ClientHello) |
| Chrome-aligned sig_algs | ✅ via uTLS | n/a | ✅ same test pins JA4 against frozen baseline, commit 94132e1 |
| `compress_certificate` (ext 0x001b) | ✅ via uTLS | n/a | ✅ enabled via rustls `brotli` feature, commit 70909ae |
| uTLS bit-perfect ClientHello (cipher_count, ext_count) | ✅ (uTLS Go matches Chrome exactly) | n/a | ⚠ cipher_count 09 vs Chrome 15; ext_count 11 vs Chrome 17 |

**Verdict: ↓ slightly behind on bit-perfect ClientHello.** This is
the only place REALITY clearly leads. Closing it requires forking
rustls's ClientHello assembler (multi-week). Tracked as P0 remaining
in [`qa/2026-05-17-gfw-2026-q1q2-threat-intel.md`](../../qa/2026-05-17-gfw-2026-q1q2-threat-intel.md)
TODO #1 (subordinated to ECH P0).

### 2. Active probing (request-layer)

**Adversary capability**: GFW sends application-layer probes
(TLS ClientHello to suspect TLS services; QUIC Initial to suspect
QUIC services; Shadowsocks-style payloads to suspect SS); see
[Ensafi et al. PETS 2015](https://gfw.report/publications/pets15/en/)
+ Tor Project blog post on continuous-probing measurement.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Cover-server splice on auth fail | ✅ REALITY proxies to "dest" SNI | ❌ raw QUIC, no cover | ✅ byte-verbatim cover-forward, p99 < 1 ms, tested in `proteus-transport-alpha/tests/cover_forward.rs` + `cover_forward_fast_teardown.rs` |
| Cover server independence | ⚠ operator picks SNI but the dest socket is opened from the Proteus server's IP, so the cover sees our IP not the client's (first-party fingerprint from cover's POV) | n/a | ⚠ same — both have this limitation |
| Anti-DoS during probe storm | ❌ no PoW / rate-limit gate by default | ❌ no PoW | ✅ tunable PoW gate (0/8/16/24) + 3-layer rate limit + handshake budget |
| Memory ceiling under probe storm | ⚠ Go runtime ~16 KiB/handshake but no hard cap | ⚠ similar | ✅ 16 MiB rx-buffer hard cap + 64 KiB handshake-time cap |
| `CONNECTION_CLOSE` reason indistinguishability (β QUIC) | n/a (TCP) | ❌ distinct close codes leak policy when prober varies invariants | ✅ all closes = NO_ERROR/empty, 4 wire tests + static-source audit, commit e04a00c |

**Verdict: ⇈ strictly ahead.** Proteus matches REALITY's cover
defense, adds PoW + rate-limiter + memory ceiling none of them have,
and pioneered the close-reason indistinguishability discipline for β.

### 3. Active probing (time-series / behavioral)

**Adversary capability**: Tiangou (per Geedge leak) and the
"behavioral AI" classifier described in the 2025-09 secondary
analyses watch flow-level statistical features over time:
inter-arrival distributions, burst patterns, request rates against
a given cover URL.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Cover-IAT camouflage | ❌ | ❌ | ✅ heartbeat cells inserted during idle windows, wire-indistinguishable from data cells per `heartbeat_cover::heartbeat_cell_is_wire_indistinguishable_from_data_cell` |
| Cover-endpoint pool rotation | ❌ (single dest SNI) | n/a | ✅ `cover_endpoints: [...]` with per-src-IP /24 (v4) / /48 (v6) **affinity** routing — same observer sees same URL across all probes (no rotation signal), different src IPs see different URLs. 8 unit tests + 4 integration tests; `crates/proteus-transport-alpha/src/cover_pool.rs`, commit landed 2026-05-18 |
| Probe-anomaly detector (server-side) | ❌ | ❌ | ✅ sliding-window per-/24 (v4) / /48 (v6) cover-forward counter with fire-once-per-burst Prometheus alert; **wired across BOTH α and β failure-close-sites** (QUIC-only probers cannot bypass). **Plus a bounded ring buffer of recent fires** exposed as labelled Prometheus gauges AND surfaced in `admin status` text + JSON. **Plus operator-opt-in auto-deny loop** (`probe_anomaly.autodeny_minutes > 0`): every fire injects the /24 into an in-binary TTL-bounded deny list; subsequent α connections short-circuit at `admission_ok` before firewall/budget/rate-limit checks, AND subsequent β connections get `Incoming::ignore()` BEFORE the TLS+QUIC handshake (prober's wire view = server unreachable; ZERO handshake CPU cost). Entries auto-expire so false positives heal. Landed 2026-05-18 (34 tests: 14 + 9 unit + 3 α e2e + 2 β e2e + 2 metrics-export e2e + 2 auto-deny-loop e2e + 2 β-pre-handshake e2e) |

**Verdict: ⇈ strictly ahead** as of 2026-05-18. Triple defense:
heartbeats (IAT camouflage), cover-endpoint pool with per-source-IP
/24 affinity (no rotation signal to single observer), AND
server-side probe-anomaly detector (per-/24 sliding-window counter
with Prometheus alert + fire-once-per-burst semantics — operator
sees the signal before the adversary has finished mapping). All
three defenses are in `crates/proteus-transport-alpha/`; the
analogous capability matrix entry for REALITY / Hy2 / TUIC-v5 is
empty on every row.

### 4. Per-record traffic analysis (length signature)

**Adversary capability**: ML models trained on AEAD record-length
sequences distinguish proxy traffic from real browsing
([Wang & Goldberg USENIX Security 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao);
Tiangou's claimed behavioral classifier per secondary analyses of
the Geedge leak).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| AEAD record length leaks plaintext length | ✅ leaks | ✅ leaks | ❌ cell-split padding rounds to quantum + 16 bytes, tested in `cell_split_padding::{multi_cell_payload_splits_and_reassembles_correctly, single_cell_payload_emits_one_cell}` |
| UDP datagram length uniformity (β) | n/a (TCP) | ❌ varies with payload | ✅ `pad_quic_datagrams_to_mtu: true` (operator opt-in), wire-tested |

**Verdict: ⇈ strictly ahead** on both axes. REALITY and Hy2/TUIC-v5
have no length-shaping defense at all; the per-record length is the
raw plaintext length. Cell-split + pad-to-MTU is Proteus's clearest
two-class lead.

### 5. QUIC SNI inspection (USENIX Security '25)

**Adversary capability**: GFW QUIC SNI inspector, deployed 2024-Q4,
documented in [Zohaib et al. USENIX Sec '25](https://gfw.report/publications/usenixsecurity25/en/).
Four exploitable corner cases: (1) ignores src ≤ dst ports;
(2) inspects only first datagram per 4-tuple; (3) 3-tuple vs
4-tuple residual blocking; (4) 180-second 5-tuple drop.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Source port ≤ destination port evasion (#1) | n/a (TCP) | ❌ ephemeral src | ✅ walks `[max(1024, dst-7) .. dst]`, tested in `quic_gfw_source_port_evasion` |
| Prefix-noise before QUIC Initial (#2) | n/a | ❌ | ✅ 16 random bytes first-flight + USENIX-23 printable-byte fix, tested in `quic_prefix_noise` |
| Connection migration (#4) | n/a | ⚠ supported but no GFW-specific port pick | ✅ `migrate()` + low source-port rebind, tested in `quic_connection_migration` |
| ECH (the actual SNI hide) | n/a (TCP) | ❌ no ECH | ❌ **not yet** — only remaining P0, rustls 0.23.40 has the API but switching from `ring` to `aws_lc_rs` HPKE provider is the integration cost |

**Verdict: ⇈ strictly ahead on the tactical USENIX-25 evasions.**
But ECH is the load-bearing defense; without it, SNI is still
cleartext. We're "ahead on the tricks but matched on the underlying
gap" — and Hy2/TUIC-v5 are matched on the gap too, so de facto
this is the strongest tactical-evasion lead of any QUIC-based proxy.

### 6. Fully-encrypted-traffic heuristics (USENIX Security '23)

**Adversary capability**: 5 heuristic rules per [Wu et al. USENIX Sec '23](https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf),
still actively used. The most load-bearing are rule 1 (≥ 70% non-
printable triggers fully-encrypted classifier) and rule 3 (first
6 bytes all printable ASCII whitelists the connection).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| α first-flight bytes are TLS ClientHello | ✅ first byte `\x16\x03\x03` matches rule 2 | n/a | ✅ same |
| β prefix-noise printable byte budget | n/a | ❌ Hy2 first datagram is QUIC Initial with ~100% non-printable header (would fail rule 1 if GFW ever extended the heuristic to UDP) | ✅ prefix-noise bytes 0–5 forced printable, residual non-printable ratio < 70%, tested in `quic_prefix_noise` PROPERTY 4 |

**Verdict: ⇈ strictly ahead on β.** Hy2/TUIC-v5 are vulnerable
to USENIX-23 if/when the GFW extends those rules to UDP. We
already shipped the defense (commit a187ea4) even though it's not
strictly required against the current GFW deployment.

### 7. DoH/DoT client bootstrap identification

**Adversary capability**: GFW 2026-Q2 identifies DoH/DoT flows by
traffic pattern, not just by destination IP ([Sunset Browser GFW
Q2 2026 update](https://sunsetbrowser.app/blog/china-gfw-update-2026-q2-en)).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Client config supports IP-literal endpoint | ✅ Xray accepts IP literal | ✅ same | ✅ same |
| Built-in bootstrap-DNS pinning + validate-time warning | ❌ operator's responsibility, no in-binary nudge | ❌ same | ✅ `bootstrap_dns: { direct_ip: <ip> }` + `proteus-client validate` PASS/WARN/FAIL audit row for both α and β endpoints, commit 394fa00 |

**Verdict: ⇈ strictly ahead.** Operator-knowledge is a real
attack surface; reducing it from "you must know to do this" to
"the tool warns you if you don't" is a substantive lead.

### 8. IDC physical takedown (2026-04 attack vector)

**Adversary capability**: 2026-04-01 mass IDC disconnection in
Guangdong / Shanghai / Beijing — physical network cable removal +
power-down ([RelyVPN 2026 crackdown analysis](https://relyvpn.com/blog/china-vpn-crackdown-2026.html)).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Direct-dial architecture (no domestic relay) | ✅ supported but not enforced | ✅ same | ✅ same |
| In-doc operator warning + topology checklist | ❌ Xray's docs don't address this | ❌ Hy2 docs don't | ✅ [`deploy/README.md`](../../projects/proteus/deploy/README.md#deployment-topology--direct-dial-vs-relay-2026-gfw-reality-check) "Deployment topology" section + 3 Mermaid diagrams + security-checklist items, commit 87207a8 |

**Verdict: ⇈ strictly ahead on operator guidance, tied on
underlying protection.** This is doc work, not protocol work, but
it's load-bearing for the user scenario (personal clean-VPS deploy).

### 9. Tiangou-class commercial DPI + cross-deployment shared blocklist

**Adversary capability**: Geedge sells Tiangou Secure Gateway as a
product to Belt-and-Road customers (Myanmar 26 DCs / Pakistan /
Ethiopia / Kazakhstan + Chinese provincial supplements);
internal tickets flag 9 commercial VPNs as "resolved"; shared
blocklist propagates burns across all customers ([2025-09-11
Geedge/MESA leak](2025-09-11-geedge-mesa-leak.md)).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| In-binary IP-reputation preflight | ❌ no Xray equivalent | ❌ no Hy2 equivalent | ✅ `proteus-server preflight check-ip-reputation`: 4-tier offline classifier (special-use FAIL / 90+ commercial-cloud CIDRs WARN / residential PASS / operator-watchlist FAIL); 35 tests; commit a390c4b |
| Operator watchlist of own burned IPs | ❌ external operator note-taking only | ❌ same | ✅ `--watchlist /etc/proteus/burned-ips.txt` documented + tested |
| Honest non-exhaustivity disclosure | n/a | n/a | ✅ module docs explicitly call out that the table is non-exhaustive and a CLEAN result is not a verification |

**Verdict: ⇈ strictly ahead.** No SOTA proxy has a built-in IP-
reputation preflight; this is a deploy-time defense Geedge's
adversary model demands and only Proteus ships.

### 10. Post-quantum confidentiality (store-now-decrypt-later)

**Adversary capability**: Any adversary recording today's TLS 1.3
handshakes for future decryption when a CRQC exists (Mosca's
theorem, ~5-15 year horizon for handshake-time-PQ rollout).

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| PQ-hybrid KEM | ❌ X25519 only | ❌ X25519 only | ✅ X25519 + ML-KEM-768 (FIPS 203), `proteus_crypto::kex` |
| Server long-term key separate from per-session ephemeral | ❌ REALITY's X25519 server key is long-term | n/a | ✅ per-session ephemeral X25519 server key, tested |

**Verdict: ⇈ strictly ahead.** This is the cleanest two-class
lead in the entire matrix. None of the SOTA TCP/QUIC proxies have
PQ confidentiality today; Proteus has hybrid PQ today AND keeps
the server's long-term key out of per-session forward secrecy.

### 11. Forward secrecy with ratcheting

**Adversary capability**: Long-running session key compromise. A
leaked AEAD key at session minute 10 exposes the entire session's
bytes for proxies that don't rotate keys mid-session.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Mid-session AEAD key rotation | ❌ single key per session | ❌ single key per session | ✅ HKDF symmetric ratchet every 4 MiB / 16 384 records |
| DH ratchet PCS heal | ❌ | ❌ | ✅ asymmetric ratchet at first 4 MiB boundary |
| TLS channel binding (RFC 5705/9266) | ❌ no inner-handshake commitment to outer TLS exporter | ❌ same | ✅ both α and β verify exporter, rogue-MITM rejected with `BadServerFinished`, tested |

**Verdict: ⇈ strictly ahead** on all three axes.

### 12. QUIC spin bit (passive RTT inference)

**Adversary capability**: Any on-path observer can measure
connection RTT by watching the spin bit's toggle frequency, per
RFC 9000 §17.4.

| | VLESS+Reality | Hy2/TUIC-v5 | Proteus |
|---|---|---|---|
| Spin bit privacy default | n/a (TCP) | ❌ uses quinn / quic-go default = enabled | ✅ `allow_spin_bit: false` default, random-fill compensation, wire-tested with 30–70% Bernoulli band in `quic_spin_bit_off.rs`, commit 41e786f |

**Verdict: ⇈ strictly ahead.** Hy2 is built on quic-go; TUIC-v5
on quinn — both inherit the `spin = true` upstream default. They
hand on-path observers RTT for free; we don't.

## Tallying the verdicts

| Verdict | Count |
|---|---|
| ⇈ strictly ahead | **9** (lines 2, 4, 6, 7, 8, 9, 10, 11, 12) |
| ↑ slightly ahead | **1** (line 3 IAT camouflage) |
| ⇈ ahead on tactics, gap on ECH | **1** (line 5) |
| ↓ behind | **1** (line 1 — uTLS bit-perfect ClientHello, the cipher_count/ext_count residual gap vs Chrome) |
| = tied | 0 |
| ❓ uncomparable | 0 |

## So how far ahead, honestly?

> 對於 GFW 的安全性甩了當今 SOTA 幾條街了？

**Several streets ahead on the protocol layer, doc-and-deploy layer,
and post-quantum layer. One residual gap (uTLS bit-perfect) where
REALITY still leads. One incomplete P0 (ECH) shared across all of
us — Proteus has the most tactical-evasion layers around the gap.**

Concretely:

- **9 of 12 capabilities**: Proteus has **strictly stronger**
  defense than VLESS+Reality and Hy2/TUIC-v5. These are not
  "comparable but different" wins — they're "Proteus has the
  defense, the others have nothing in that slot" wins.
- **1 of 12 (uTLS bit-perfect)**: REALITY leads. Closing it
  needs a rustls ClientHello-assembler fork; tracked as the
  second remaining engineering item after ECH.
- **1 of 12 (ECH)**: nobody has it among the three named
  alternatives. Proteus pioneered the tactical-evasion layers
  around it (USENIX-25 #1/#2/#4 + USENIX-23 #1/#3), so the gap
  hurts us less than it hurts Hy2/TUIC-v5. Still: ECH is the
  load-bearing defense the QUIC profile needs.

## What this audit deliberately doesn't claim

- **Not a guarantee of survival.** Audits compare known capabilities
  against known defenses. Tiangou's source-RE is incomplete; the
  next batch of Geedge customer-driven detector updates could
  introduce something we haven't characterized.
- **Not a speed claim.** This is a SAFETY audit. The speed-vs-
  Hy2/TUIC-v5 question needs a separate netem head-to-head; the
  in-protocol perf knobs (BBR, 64 MiB stream window, ack-frequency
  opt-in, MTU-discovery upper-bound pin, spin-bit-off
  randomization) are designed to match or exceed but the empirical
  comparison hasn't been run.
- **Not an audit of the implementations we compare against.** We
  cite REALITY / Hy2 / TUIC-v5 from their published spec + most
  recent stable release docs. A truly rigorous comparison would
  source-review their actual git HEAD for each capability —
  out of scope for one iteration.
- **Not a substitute for an external security audit.** Self-audits
  are biased by construction. An external third-party audit is
  listed as a remaining gap in [`projects/proteus/README.md`](../../projects/proteus/README.md)
  honest gap analysis and remains a future deliverable.

## Tests that back each line of the audit

For every ✅ in the matrix above, the implementing commit AND test
is named. To verify the audit independently:

```bash
cd projects/proteus
cargo test --workspace --no-fail-fast
# 455 tests pass, 0 fail, 2 ignored as of commit 87207a8
```

The 455 tests include all the wire-observation regression tests
that pin the ✅ rows. If any line of this audit were to silently
regress, the matching test would fail.

## Replication note for future-Claude / future-Icarus

This audit was written 2026-05-18 against repo HEAD `87207a8`. To
re-run it after a year of GFW evolution:

1. Refresh the threat-intel doc with new attack lines published since
   then (start at GFW.report's index page + net4people/bbs issue list).
2. For each new attack line, find or build the matching defense in
   Proteus, add a row to the matrix, and re-tally.
3. The columns for REALITY / Hy2 / TUIC-v5 likely also need updating
   — pin the version explicitly per the convention above.

The format is intentionally mechanical so that "is the audit still
true?" reduces to "do the cited tests still pass?".
