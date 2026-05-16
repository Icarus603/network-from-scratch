# How China Detects and Blocks Shadowsocks
**Venue / Year**: ACM Internet Measurement Conference (IMC) 2020, pp. 111–124
**Authors**: Alice, Bob, Carol (GFW Report); Jan Beznazwy (independent); Amir Houmansadr (UMass Amherst)
**Read on**: 2026-05-16 (in lesson 9.2)
**Status**: full PDF (mirror: `https://censorbib.nymity.ch/pdf/Alice2020a.pdf`); slides at `https://gfw.report/talks/imc20/`
**One-line**: GFW deploys a two-stage detector (entropy/length screening + 7-class active probing) against Shadowsocks (including AEAD), driven by ≥12 000 prober IPs orchestrated by a small central pool.

## Problem
Shadowsocks (SS) is the dominant circumvention tool in mainland China. Since May 2019, residential users reported sporadic SS blocking with hours-to-days latency relative to first use. No prior measurement existed for **how** GFW finds SS servers, especially given that SS has no plaintext framing.

## Contribution
1. First end-to-end characterisation of GFW's SS detection pipeline, validated by 4 months of in-vivo measurement (29 Sep 2019 → 21 Jan 2020) using 5 Tencent Beijing clients ↔ 5 DigitalOcean UK servers running `shadowsocks-libev` and Outline.
2. Decomposition of the prober pool into ≥12 000 IPs whose TCP timestamps cluster into a small set of sequences — implying centralised orchestration despite distributed source IPs.
3. Disclosure to SS developers led to AEAD-version mitigations and the `brdgrd` workaround that survives the entropy test.

## Method
- **Server instrumentation**: log every probe (timestamp, src IP/port, payload hash, length, response state) at the SS server.
- **Replay vs random probes** are distinguished by hashing payloads against captured legitimate client packets with 1–12 byte mutations at fixed offsets.
- **Passive trigger condition**: GFW marks a flow as "candidate SS" iff:
  - first data segment has length **L** with high byte-entropy (no recognisable protocol header), AND
  - **L mod 16 ∈ {2, 9}**, AND
  - **L** within ranges {160–384} (for the 9-mod) or {264–700} (for the 2-mod).
  These ranges align with the popular SS-libev AEAD record size after `[salt | encrypted-length | encrypted-payload]`.
- **Active probing (within seconds to minutes of the trigger)** uses 7 probe families:
  1. Replay of the captured first segment, verbatim.
  2. Replay with 1 byte mutated at offset 0 (auth-tag end).
  3. Replay with 1–12 bytes mutated at fixed positions.
  4. Random payload, length 221 bytes.
  5. Random payload, length-class matching the trigger.
  6. Truncated replay (first N bytes only, N < L).
  7. Concatenated replays (back-to-back two recorded streams).
  Server's behaviour (early FIN / RST / timeout / data echo) is then compared against the SS server's fingerprint: an SS server that fails AEAD authentication holds the socket open indefinitely → distinct from random servers that immediately FIN/RST.

## Results
- Across 4 months, observed **>50 000 probes from >12 000 distinct prober IPs**.
- **Centralisation evidence**: TCP timestamp values across probers cluster into a tiny number of monotonic sequences with consistent slopes, i.e. shared kernel clocks. Source-port distribution also biased to Linux ephemeral range (32768–60999). Conclusion: hundreds of unique source IPs share a common machine.
- **Blocking outcome**: SS server can be (a) not blocked, (b) ports-only blocked, (c) full-IP blocked. Probabilistic; correlates with politically sensitive dates (e.g. October 1 2019).
- **Workarounds**:
  - `brdgrd`-style server-side TCP window-size shrinkage forces clients to send the first record in two segments → splits across packets, breaking the length-entropy trigger.
  - Outline 1.0.10+ coalesces consecutive small writes to spike `L` outside the 160–700 range.
  - AEAD ciphers + the 30-second silent-hold mitigation defeat **probe families 1–6** (random/replay) since server response is identical to a stuck-on-read state.

## Limitations / what they don't solve
- Workarounds are reactive; GFW can extend the trigger window and add more probe families. The 2023 USENIX paper (Wu et al., [[wu-fep-detection]]) shows GFW did exactly that for fully-encrypted-traffic (FET) heuristics.
- The work does not characterise the ML-based or stateful flow analysis path. Prober-source diversity may be intentionally heterogeneous and may hide a stateful tracker.

## How it informs our protocol design
- **First-packet entropy is a fingerprint**. Our protocol's first-packet either (a) carries a plausible TLS/QUIC/HTTP header (REALITY route) or (b) is length-coded outside the SS trigger ranges and split across segments by design — never a single high-entropy blob 160–700 bytes.
- **Probe-tolerance**: server must respond to *any* malformed first record exactly as a real TLS/HTTP server would respond to garbage on its honest port — the closer to byte-for-byte mimicry of the cover server's failure-path response, the smaller the active-probing signal.
- **Multi-IP prober anti-pattern**: counting probes by source IP under-estimates probing activity. Telemetry must hash by `(src-subnet, timestamp-cluster)`.

## Open questions
- What fraction of SS detection was passive vs active in 2024–2026? Has the entropy trigger been replaced by ML?
- Does GFW's prober pool ever issue post-auth probes (e.g. valid SS handshake followed by anomalous payload)? Unknown.
- Could a server reliably detect probes from honest clients using only network-layer features (TCP TS clustering, port-range bias) without active provocations?

## References worth following
- Ensafi et al. *Examining How the Great Firewall Discovers Hidden Circumvention Servers.* IMC 2015 → [[ensafi-gfw-probing]] (active probing on Tor/obfs2/obfs3).
- Wu et al. *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic.* USENIX Security 2023 → [[wu-fep-detection]] (FET detection generalises the 2020 work).
- Frolov, Wampler, Wustrow. *Detecting Probe-resistant Proxies.* NDSS 2020 → [[frolov-probe-resistant-ndss20]].
- Cao et al. *Off-Path TCP Exploits.* USENIX Security 2016 → [[cao-tcp-side-channel]] (TCP timestamp side-channel formalism used to argue centralisation).
