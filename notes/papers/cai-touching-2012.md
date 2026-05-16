# Touching from a Distance: Website Fingerprinting Attacks and Defenses
**Venue / Year**: ACM CCS 2012
**Authors**: Xiang Cai, Xin Cheng Zhang, Brijesh Joshi, Rob Johnson
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: First "attack + defense" pair paper for WF; edit-distance SVM kernel attack (70%+ on Tor), and BuFLO defense.

## Problem
Existing WF work treated attacks and defenses separately. A coherent attack-defense study could quantify trade-offs.

## Contribution
1. **Attack**: edit-distance (Damerau-Levenshtein) kernel SVM on cell sequences. ~70% on 800 Tor sites.
2. **Defense**: BuFLO — constant-rate channel with minimum duration. Reduces attack to ~5%.
3. First explicit attack-defense codesign.

## Method
- Edit distance on cell direction sequences.
- String kernel SVM.
- BuFLO: send packet every $1/\rho$ seconds, fixed size $s$, minimum duration $T_{\min}$.

## Results
- Attack 70%+ on 800 sites.
- BuFLO drops to ~5–14% (200%+ overhead).

## Limitations
- BuFLO too expensive.
- Edit distance computationally expensive on large datasets.

## How it informs our protocol design
- Codesign attack-defense — useful for G6 evaluation methodology.
- BuFLO is the formal indistinguishability baseline.

## References worth following
- Cai 14 CCS (Tamaraw) — improved BuFLO
- Wang 14 USENIX Sec — k-NN attack
