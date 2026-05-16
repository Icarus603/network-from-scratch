# How China Detects and Blocks Shadowsocks
**Venue / Year**: IMC 2020 (ACM Internet Measurement Conference)
**Authors**: Alice, Bob, Carol (gfw.report pseudonyms), Jan Beznazwy, Amir Houmansadr
**Read on**: 2026-05-16 (in lessons 11.1, 11.3, 11.7, 11.12 of Part 11)
**Status**: abstract + key findings; full PDF at https://censorbib.nymity.ch/pdf/Alice2020a.pdf and gfw.report
**One-line**: Reveals the two-stage GFW detection pipeline for Shadowsocks — passive packet-entropy + length classification, then active probing — and quantifies that detection triggers within 13 connections.

## Citation correction
This paper is sometimes wrongly attributed to Frolov et al. (who authored adjacent FOCI 2020 work "HTTPT: A Probe-Resistant Proxy"). The actual authors of "How China Detects and Blocks Shadowsocks" are Alice/Bob/Carol (gfw.report) + Beznazwy + Houmansadr, published at IMC 2020 not FOCI 2020. Part 11 lessons that say "Frolov FOCI 2020 SS detection" should be read as referring to this paper, with attribution updated.

## Problem
Shadowsocks (SS) was the most widely deployed circumvention tool to/from mainland China for many years. In 2019-2020, GFW began systematically blocking SS servers. This paper instruments and measures how.

## Contribution
- Two-stage pipeline confirmed:
  - **Stage 1 (passive)**: classify flow by (length, entropy) of first data packet. SS's ciphertext is uniform-random by design (no plaintext framing) → high entropy distinguishes it from TLS / HTTP / etc.
  - **Stage 2 (active)**: GFW dispatches probes from thousands of source IPs to suspected servers, including:
    1. Replays of past genuine SS connections (subset).
    2. Random-bytes probes of varied lengths.
    3. Variations targeting specific SS cipher families.
- Trigger threshold: ~13 genuine client connections suffices to attract first probe. First probes arrive within seconds.
- Probe source IPs are diverse but centrally coordinated (network side-channel evidence).
- Block effect: drops server's outgoing packets (port-specific or whole-IP).

## Method
- Run controlled SS servers; measure GFW response.
- Vary SS implementation, cipher, packet shape.
- Use Bayesian inference + traffic-level statistics.

## Results
- High entropy + short first packet ≈ near-certain SS classification.
- Probe replay is partial; sometimes only first few bytes.
- Block rate scales with deployment popularity of given SS variant.

## Limitations / what they don't solve
- Doesn't fully reverse-engineer probe scheduler.
- Mitigation suggestions (packet coalescence, entropy shaping) are partial.

## How it informs our protocol design
- G6's CAR-1 budget directly references entropy + length features as the attack surface to defeat.
- G6's per-packet 1280B cell padding addresses length feature.
- G6's authentication-by-HMAC (not by AEAD attempt) addresses entropy feature: the first 32 bytes are HMAC pseudorandom, AAD-fixed, embedded in TLS ClientHello extension whose entropy is structured.
- G6's REALITY-style cover forward addresses Stage 2 active probing.

## Open questions
- Has GFW's classifier shifted to DL-based since 2020? Public measurement gap.
- What's the long-term trend of trigger threshold (13 → less)?
- Does GFW have similar pipeline for Trojan/VLESS/Hysteria2? Partial evidence yes.

## References worth following
- gfw.report public blog (continuous updates)
- Bock et al. CCS 2020 "Detecting and Evading Censorship-in-Depth" — companion deep-dive
- net4people/bbs GitHub for community discussion
- Wu et al. USENIX 2023 "FEP" — newer DL-based attacks
