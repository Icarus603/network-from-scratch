# ScrambleSuit: A Polymorphic Network Protocol to Circumvent Censorship
**Venue / Year**: WPES 2013 (Workshop on Privacy in the Electronic Society)
**Authors**: Philipp Winter, Tobias Pulls, Juergen Fuß
**Read on**: 2026-05-16 (in lesson 10.6)
**Status**: full PDF
**One-line**: Per-client polymorphic Tor PT with probing-resistant handshake — direct predecessor of obfs4.

## Problem
obfs3 used static handshake, allowing GFW to detect bridges via active probing. Need a PT where each client-bridge pair has unique session keys and the bridge is unresponsive to unauthenticated probes.

## Contribution
1. Per-client shared secret (out-of-band distribution).
2. Probe-resistant: bridge silent on missing/incorrect HMAC.
3. Polymorphic wire format: packet sizes drawn from a randomized distribution; IATs similarly.
4. UniformDH adapted from obfs3.

## Method
- Out-of-band shared secret distribution (private bridge address book).
- Client connects, sends HMAC(secret, key_material).
- Bridge verifies HMAC; if invalid, ignore.
- After auth: each side derives unique session keys; padding pattern parameterized by secret.

## Results
- Probing-resistant bridge: 0% naive active-probing detection.
- Polymorphic wire: harder to fingerprint than fixed obfs3 pattern.
- Deployed as ScrambleSuit PT in Tor 2013–2014.

## Limitations
- High-entropy wire (still vulnerable to entropy DPI).
- Replaced by obfs4 (Yawning Angel 14) which generalized the design.
- Per-client shared secret distribution is a deployment burden.

## How it informs our protocol design
- **HMAC-based probe-resistance is the canonical pattern** — Proteus should include analogous mechanism (or REALITY-fallback as superior alternative).
- Per-client polymorphism reduces some statistical attacks but does not solve high-entropy wire.
- Out-of-band key distribution doesn't scale — Proteus should use REALITY-style server-key-derived signaling.

## Open questions
- Polymorphism with constrained byte distributions (low-entropy bytes via FTE)?
- Per-client polymorphism in modern post-FEP-detection era?

## References worth following
- obfs4 spec (yawning/obfs4proxy) — successor
- Frolov 20 NDSS — probing-resistance detection
- REALITY spec — modern alternative
