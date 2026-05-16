# A Mechanised Cryptographic Proof of the WireGuard Virtual Private Network Protocol
**Venue / Year**: IEEE EuroS&P 2019
**Authors**: Benjamin Lipp, Bruno Blanchet, Karthikeyan Bhargavan
**Read on**: 2026-05-16 (in lesson 11.10 of Part 11; pre-existing Part 5 reference)
**Status**: abstract + main results from EuroS&P 2019 proceedings; full PDF available from author homepages
**One-line**: First end-to-end mechanised cryptographic proof of WireGuard (Noise IK handshake) using ProVerif + CryptoVerif, establishing secrecy, mutual auth, forward secrecy, KCI resistance.

## Problem
WireGuard (Donenfeld NDSS 2017) was widely deployed but had only informal security argument. The handshake (Noise IK pattern) needed mechanised verification.

## Contribution
- ProVerif model of full WireGuard handshake.
- CryptoVerif companion for computational-level bounds.
- Verified properties:
  - Secrecy of session keys
  - Mutual authentication
  - Forward secrecy
  - KCI (key compromise impersonation) resistance
  - Identity hiding for initiator
- Source code (.pv file) made public for reuse.

## Method
- Hand-translated WireGuard spec into applied pi-calculus.
- Used standard ProVerif queries.
- CryptoVerif for game-based reduction proofs.

## Results
- All properties verified in symbolic model.
- Found minor spec ambiguities resolved in collaboration with Donenfeld.

## Limitations / what they don't solve
- Symbolic model assumes perfect crypto.
- Doesn't address implementation bugs.
- Doesn't address timing/side-channel.

## How it informs our protocol design
- G6 ProVerif model (G6Handshake.pv) directly inspired by this work's structural style.
- Confirms Noise IK is a reasonable "off-the-shelf" handshake (G6 explored Noise IK as candidate before settling on TLS 1.3-borrowed in 11.6).
- Cross-tool composition (ProVerif + CryptoVerif) sets precedent for G6 future v0.2 computational-level verification.

## Open questions
- CryptoVerif library for hybrid PQ KEM? Not yet mature.
- Compositional reasoning across ProVerif + Tamarin? Manual today.

## References worth following
- Donenfeld NDSS 2017 (WireGuard original)
- Donenfeld-Milner 2018 technical report (formal verification informal predecessor)
- Kobeissi-Bhargavan EuroS&P 2017 (Noise Explorer foundation)
- Blanchet CSFW 2001 (ProVerif foundation)
