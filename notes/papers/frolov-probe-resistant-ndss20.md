# Detecting Probe-resistant Proxies
**Venue / Year**: NDSS 2020
**Authors**: Sergey Frolov, Jack Wampler, Eric Wustrow (CU Boulder)
**Read on**: 2026-05-16 (in lessons 9.3, 9.6, 9.12)
**Status**: full PDF (`https://www.ndss-symposium.org/wp-content/uploads/2020/02/23087.pdf`)
**One-line**: Even probe-resistant proxies (obfs4, Lampshade, SS-AEAD, MTProto, OSSH) betray themselves via TCP-level side-channels (timeout vs FIN vs RST thresholds on incomplete authentication payloads), letting a censor build a decision tree that confirms suspected proxies with negligible false positives.

## Problem
"Probe-resistant" proxies (obfs4, SS-AEAD, etc.) silently hold sockets when a probe fails authentication, defeating naive byte-pattern probing. Question: are there observable side-channels — outside the authentication payload — that still distinguish them from arbitrary TCP servers?

## Contribution
1. Identifies a generic vulnerable code pattern: the proxy reads a fixed minimum number of bytes, authenticates, then either echoes or holds. The buffer-flushing behaviour at FIN time leaks the read-length boundary.
2. Provides a six-protocol comparison (obfs4, Lampshade, SS Python AEAD, SS Outline AEAD, MTProto, OSSH) with reproducible decision trees.
3. Disclosure-driven fixes (obfs4 0.0.11 in 2019-06-21, Outline in 2019-09, Psiphon OSSH in 2019-05-13).

## Method
- Construct probe set: payload sizes spanning the auth boundary `± few bytes`. Example: if the proxy reads exactly 50 bytes before auth, send {49, 50, 51, 52, 100, 200} byte payloads.
- For each (probe size, target), record (a) bytes-received-before-close, (b) FIN vs RST, (c) timeout duration if no close, (d) any reply data.
- Compare against (a) random ZMap-discovered TCP servers (1.5 M IPs), (b) university-tap passively observed servers (0.4 M IP:port pairs).

## Results — key protocol fingerprints
- **obfs4** read 49 bytes then auth-checks the obfs4-handshake hash. Concretely:
  - 49 bytes → server times out 30 s, closes with FIN.
  - 50 bytes → server FIN-closes immediately (handshake auth failed).
  - 51 bytes → server RST-closes (auth failed, leaving 1 byte unread in kernel buffer; Linux sends RST instead of FIN when closing with unread data).
- **Lampshade** has a similar 64-byte boundary with FIN/RST asymmetry.
- **SS-AEAD (Python)** held idle when handshake failed, but the response to a TLS-style probe (sending `0x16 0x03 0x01 ...`) was distinct from a real TLS server (no Alert).
- **SS-Outline (AEAD)** initially had the same problem; mitigation: 30-second silent-hold + AEAD before close.
- **OSSH (Psiphon)** had timing patterns and FIN behaviour that produced 7/8 correct identifications in their evaluation.
- **MTProto** never closes the connection, never times out → **the only protocol that survives the attack** in their evaluation. Recommendation: every probe-resistant proxy should adopt "read until client gives up" semantics.

## Limitations / what they don't solve
- Attack assumes a censor can issue active probes from many IPs (GFW-class resource). Smaller censors cannot scan ZMap-scale.
- Decision tree must be re-derived per protocol update; long-term arms race.
- Does not address passive-only detection (entropy, packet timing) — those are orthogonal.

## How it informs our protocol design
- **Hard rule**: server must respond to any malformed handshake exactly like a real cover protocol (TLS/HTTP). REALITY's "hand-off to a real backend" pattern is the right move because the cover backend's response distribution is the truth.
- **No fixed-length read before auth**. Use streaming AEAD or chunked authentication so there's no boundary-byte to find.
- **Drain client until client closes**, never close the socket ourselves on auth failure. MTProto-style perpetual reader is the safest pattern.
- **Buffer hygiene**: avoid the Linux `RST-on-unread-data` leak. Either drain via `shutdown(SHUT_RD)` first, or rely on application-level long-poll.

## Open questions
- Are there higher-order side channels (kernel timing, congestion-window initial value) that survive even the MTProto strategy?
- Can a censor scale this attack to all suspected proxies in real time, or is it post-hoc forensics?

## References worth following
- Wang, Dong, Murdoch, Lindell. *Seeing Through Network-Protocol Obfuscation.* CCS 2015 (precursor: first systematic active probing of obfs2/obfs3/SS).
- Houmansadr et al. *The Parrot is Dead.* IEEE S&P 2013 → [[houmansadr-parrot-is-dead]].
- Alice, Bob, Carol. *How China Detects and Blocks Shadowsocks.* IMC 2020 → [[alice-bob-carol-ss-imc20]].
- Bock et al. *Geneva.* CCS 2019 → [[bock-geneva-ccs19]] (the dual: evading rather than detecting).
