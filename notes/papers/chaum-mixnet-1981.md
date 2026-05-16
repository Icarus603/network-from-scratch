# Untraceable electronic mail, return addresses, and digital pseudonyms
**Venue / Year**: Communications of the ACM, February 1981
**Authors**: David Chaum
**Read on**: 2026-05-16 (in lesson 10.9)
**Status**: full PDF (in CACM archive)
**One-line**: Foundational paper of anonymous-communication systems; introduced the mix network concept that all later mixnets and Tor derive from.

## Problem
1980s, growing electronic mail networks. Need to enable sender anonymity (and pseudonymous responses) despite a global passive adversary able to observe the entire network.

## Contribution
1. **Mix concept**: a server that receives encrypted batched messages, decrypts the outer layer, shuffles their order, and forwards.
2. **Onion encryption**: layered encryption with per-hop keys.
3. **Return addresses**: anonymous reply via single-use return-path tokens.
4. **Digital pseudonyms**: pseudonyms linked to message but not to identity.

## Method
- Sender prepares a message wrapped in $N$ layers of encryption, one per mix in the path.
- Each mix peels its layer, queues the message, releases in random order after a batch.
- Sender's identity revealed only to mix 1 (network-layer); content visible only to receiver.

## Results
- Conceptual foundation; no implementation in the paper.
- Spawned: Babel, Mixmaster, Mixminion, Tor, Loopix, Nym.

## Limitations
- High latency due to batching.
- Vulnerable to active flooding attacks (one sender per mix).
- Tag attacks (Pfitzmann 1993) defeat naive implementations.
- No analysis of cover traffic — that came later.

## How it informs our protocol design
- **Onion-encryption pattern is a fundamental tool** — G6 may use 1-hop trust by default but support multi-hop optional.
- The "batched shuffle" is incompatible with low-latency web — G6 uses encrypted point-to-point instead.
- Conceptual: every CRS designer should know this paper.

## Open questions
- Modern variations: see Mixminion, Loopix, Nym.

## References worth following
- Mixminion 03 — typed-anonymous-remailer descendant
- Chaum 1988 (Dining Cryptographers Protocol) — alternative anonymity primitive
- Tor design paper (Dingledine 04 USENIX Sec) — low-latency descendant
