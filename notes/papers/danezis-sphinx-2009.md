# Sphinx: A Compact and Provably Secure Mix Format
**Venue / Year**: IEEE S&P 2009
**Authors**: George Danezis, Ian Goldberg
**Read on**: 2026-05-16 (in lesson 10.9)
**Status**: full PDF
**One-line**: Fixed-size mixnet packet format with formal security proof for sender/receiver indistinguishability; standardized in Loopix/Nym.

## Problem
Mixnet packet formats (Mixmaster, Mixminion) had ad-hoc designs; some had vulnerabilities to active attacks. Need a clean, formally-secure packet format.

## Contribution
1. Fixed-size packet that can be onion-decrypted at each hop without revealing size leak.
2. Reply blocks (SURBs) integrated cleanly.
3. Formal indistinguishability proof.

## Method
- Each packet: header (per-hop) + payload + MAC.
- Per-hop key derived via Diffie-Hellman with mix's public key.
- Padding maintains fixed total size at each layer.

## Results
- ~256-byte header, configurable payload.
- Provably secure against passive + active adversaries.

## Limitations
- Per-hop crypto cost.
- Fixed packet size limits throughput flexibility.

## How it informs our protocol design
- Sphinx packet format is the modern mixnet packet building block.
- Proteus multi-hop mode (if added) should use Sphinx-style packets.

## References worth following
- Mixminion (S&P 03)
- Loopix (USENIX Sec 17)
