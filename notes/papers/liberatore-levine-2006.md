# Inferring the Source of Encrypted HTTP Connections
**Venue / Year**: ACM CCS 2006
**Authors**: Marc Liberatore, Brian Neil Levine
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: Scaled WF attack to 1000–2000 HTTPS sites with multinomial Naïve Bayes / Jaccard, achieving ~75% closed-world accuracy.

## Problem
Hintz 02 demonstrated WF on 5 sites. Does it scale to realistic site count?

## Contribution
1. Dataset: 1000+ HTTPS sites with multiple visits each.
2. Multinomial NB on packet sizes as sequence.
3. Jaccard coefficient variant for set-based comparison.
4. ~75% closed-world accuracy.

## Method
- Per-trace feature: vector of packet sizes (in order).
- Multinomial NB models packet-size emission per site.
- Alternative: trace as set of sizes, Jaccard similarity.

## Results
- ~75% closed-world (1000 sites, 100 visits/site).
- VPN doesn't help: VPN preserves packet sizes.

## Limitations
- HTTPS-only, pre-Tor.
- Closed-world; no open-world analysis.
- No defense.

## How it informs our protocol design
- Establishes leakage scale: 75% on 1000 sites is significant.
- HTTPS + ordinary VPN ≠ private; G6 must shape sizes.

## References worth following
- Hintz 02 — predecessor
- Herrmann 09 CCSW — Tor-application
- Wang 14 USENIX Sec — feature-engineering culmination
