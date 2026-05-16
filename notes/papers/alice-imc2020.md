# How China Detects and Blocks Shadowsocks
**Venue / Year**: ACM IMC 2020 (October 27–29, 2020, Virtual Event)
**Authors**: Alice, Bob, Carol (GFW Report, pseudonymous), Jan Beznazwy, Amir Houmansadr (UMass Amherst)
**DOI**: 10.1145/3419394.3423644
**Read on**: 2026-05-16 (in lesson 7.2)
**Status**: full PDF (cached at `assets/papers/imc-2020-alice.pdf`, mirrored from CensorBib)
**One-line**: The GFW detects Shadowsocks by combining a passive entropy + length filter on the first data packet with a follow-up suite of active probes that exploits implementation-specific behaviour to confirm the guess and then blacklist the server.

## Problem
Since May 2019, Shadowsocks (SS) servers in China started getting blocked unpredictably, but no one had a public, reproducible explanation of *how* the GFW was finding them. Because SS is a fully-encrypted protocol with no plaintext framing, naive DPI shouldn't work — yet the blocking was clearly targeted, not random.

## Contribution
1. First end-to-end measurement of GFW's two-stage Shadowsocks pipeline: passive flow filter → active probe → blacklist.
2. Characterises the **passive heuristic**: high-entropy first packet whose length falls in suspicious ranges (replay range ~160–700 bytes mod 16; non-replay probes concentrate at exactly 221 bytes).
3. Catalogues **seven probe families** the GFW deploys (replayed client packets vs. random-payload probes of various lengths) and reverse-engineers what each tries to confirm.
4. Releases a **prober simulator** that lets defenders reproduce GFW probes locally against any SS implementation.
5. Fingerprints the prober infrastructure: 50,000+ probes from 12,000+ source IPs across 4 months, all geolocating to China — meaning IP-based blocking of probers is hopeless.

## Method (just enough to reproduce mentally)
- Rented servers outside China running shadowsocks-libev and Outline; clients inside China generated authentic traffic.
- Parallel **control servers** that nobody legitimately connected to, to separate GFW probing from background internet scanning.
- All ingress packets logged for ~4 months; probes correlated with prior legitimate connections to derive the trigger model.
- Built a probe-replay simulator to test each candidate Shadowsocks implementation under each observed probe, learning which side-channel (response length, RST timing, connection-close behaviour) the GFW reads.

## Results
- The trigger threshold is **small** — as few as ~13 client connections can elicit probing; AEAD ciphersuites raise the bar slightly but do not eliminate it.
- First probe usually arrives within **seconds** of a real connection landing on the server.
- Probes split into two families: (a) **replayed** copies of real client first-packets to test for replay-filter absence, (b) **random-payload** probes (the 221-byte one being the signature) to elicit characteristic error responses.
- shadowsocks-libev (pre-replay-filter) and older variants leak via predictable connection-close timing; Outline mitigates some via packet coalescing but is still detectable.
- Once confirmed, the GFW drops packets **from the server's IP:port**, sometimes server-wide, sometimes only during politically sensitive windows — confirming a human-in-the-loop layer.

## Limitations / what they don't solve
- Cannot see GFW internals — all inferences are black-box from the probe side.
- Doesn't measure detection of UDP-mode SS, SSR, or v2ray.
- Probe taxonomy is empirical for the 4-month window; GFW has updated since (see Wu et al. USENIX Security 2023 for the purely-passive successor system).
- Mitigations proposed (replay filter, length padding, `brfdgrd`) buy time, not immunity.

## How it informs our protocol design
This is the canonical existence proof that **"looks like random bytes" is not a security property** against the GFW. Any Phase III design has to assume:
1. The censor performs **active probing** on suspicious flows — protocol must be safe even when an adversary replays or fuzzes the first packet (cf. REALITY's authenticated handshake forwarding).
2. Length and entropy of the **first data packet** are first-class observables — pad/shape deliberately, do not leave a 221-byte fingerprint.
3. Implementation-level side channels (close timing, RST patterns, error responses) leak as much as the wire format — the spec must mandate constant-time/constant-shape failure paths.
4. Blocking is per-(IP, port), so port hopping or multi-port designs (Hysteria2, TUIC) buy resilience but only after detection — better not to be detected at all (Part 7.4 / 7.5 will revisit).

## Open questions
- What is the GFW's exact entropy estimator? Shannon over fixed window? Compression-ratio proxy?
- How does the prober pool refresh — botnet, residential proxies, or dedicated infra?
- Can a protocol be designed whose first packet is **provably indistinguishable** from a target cover protocol (TLS 1.3 ClientHello) under both passive and active probing? (REALITY claims yes; formal proof open — Part 11.10.)

## References worth following
- Ensafi et al., FOCI 2015 — earlier active-probing study (`notes/papers/ensafi-gfw-probing.md`).
- Wu et al., USENIX Security 2023 — purely passive FEP detection, the successor system (`notes/papers/wu-fep-detection.md`).
- Houmansadr et al., NDSS 2013 — *The Parrot is Dead* (`notes/papers/houmansadr-parrot-is-dead.md`).
- gfw.report talk page: <https://gfw.report/talks/imc20/en/>
- Shadowsocks-libev replay-filter patches (post-paper) — `shadowsocks-libev` GitHub issues #2621 onward.
