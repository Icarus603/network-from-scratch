# Network flow watermarking: A survey
**Venue / Year**: IEEE Communications Surveys & Tutorials 2017
**Authors**: Alfonso Iacovazzi, Yuval Elovici
**Read on**: 2026-05-16 (in lesson 10.7)
**Status**: full PDF
**One-line**: Comprehensive survey of active flow watermarking attacks: inject specific patterns into traffic and detect them downstream to confirm same-flow identity across anonymizing networks.

## Problem
Passive flow correlation (Murdoch 05, Nasr 18 DeepCorr) requires statistical analysis. Active watermarking trades on lower data requirements: inject a specific signal, look for it elsewhere.

## Contribution
Survey of:
1. Interval-based watermarking (Wang-Reeves 03)
2. Inter-packet-delay watermarking (Wang-Chen-Jajodia 05)
3. Spread-spectrum (Yu-Zhao-Le-Ling 07)
4. RAINBOW (Houmansadr-Borisov 12)
5. DropWat (Iacovazzi 20)

## Method
- Each technique modulates a feature (timing, size, count) with a known pattern.
- Detector at downstream looks for the pattern.
- Trade-offs: detection rate vs visibility to defender.

## Results
- Watermarks with low overhead (<5%) detectable at 90%+ rate.
- Defense: random jitter / padding degrades but doesn't eliminate.

## Limitations
- Survey only — no new attack.

## How it informs our protocol design
- Proteus timing module must defend against watermarking (random jitter ≥ 25ms).
- Active attacker is realistic, especially state-level.

## References worth following
- Wang-Reeves 03 (interval) — earliest
- Houmansadr 12 (RAINBOW) — invisible-to-attacker watermark
- Nasr 18 (DeepCorr) — passive correlation alternative
