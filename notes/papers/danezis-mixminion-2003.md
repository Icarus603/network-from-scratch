# Mixminion: Design of a Type III Anonymous Remailer Protocol
**Venue / Year**: IEEE S&P 2003
**Authors**: George Danezis, Roger Dingledine, Nick Mathewson
**Read on**: 2026-05-16 (in lesson 10.9)
**Status**: full PDF (publicly available)
**One-line**: Production-grade anonymous remailer with single-use replyable forward anonymity, integrating cover traffic and exit policies.

## Problem
Mixmaster (Cottrell 1995) lacked replay protection, exit policies, robust path selection. Need a clean redesign incorporating decade of cryptographic insight.

## Contribution
1. Single-use reply blocks (SURBs) for receiver-anonymous replies.
2. Cover traffic injection at each mix (dummy messages alongside real).
3. Exit policies for mixes to refuse certain destinations.
4. Strong directory authority for mix discovery.

## Method
- Path: sender chooses ~N=5 mix path.
- Each message: onion-encrypted with per-hop key.
- Each mix: decrypt, queue, release in random shuffle.
- Replay detected via per-mix message ID cache.
- SURBs: receiver pre-generates encrypted return path tokens.

## Results
- Production mixnet operating 2003–2010s.
- Anonymity properties formally analyzed by subsequent works (Serjantov 04 et al.).

## Limitations
- Hour-level latency.
- Mix server discovery centralized.
- Sphinx packet format (Danezis 09) later replaced Mixminion's packet design.

## How it informs our protocol design
- **G6 doesn't pursue Mixminion's high-latency design** for general use.
- Cover-traffic concept (Mixminion injects per-mix dummies) generalizes to G6 light-cover mode.
- SURB-style return-anonymity not directly relevant unless G6 adds messaging mode.

## Open questions
- Tor's design (low-latency successor) trades formal anonymity for usability — different design space.

## References worth following
- Chaum 1981 — predecessor
- Sphinx 2009 (Danezis-Goldberg) — modern packet format
- Loopix 2017 — modern Mixminion analog
