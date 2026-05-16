# k-fingerprinting: A Robust Scalable Website Fingerprinting Technique
**Venue / Year**: USENIX Security 2016
**Authors**: Jamie Hayes, George Danezis
**Read on**: 2026-05-16 (in lessons 10.2, 10.5)
**Status**: full PDF (publicly available)
**One-line**: Random-forest + leaf-encoding-k-NN attack with 175 hand-crafted features; SOTA hand-crafted WF accuracy (95%+) and a feature-importance ranking used by all subsequent defenses.

## Problem
By 2016 several WF attacks exist (k-NN Wang 14, CUMUL Panchenko 16) but each has weaknesses: k-NN is slow on large datasets, CUMUL's 100-dim cumulative feature is somewhat lossy. Defenders also lack guidance on which features matter most.

## Contribution
1. Curated 175 hand-crafted features: packet counts, time, concentration (in/out ratios at sub-intervals), bursts, sizes, alternative concentrations.
2. Two-stage classifier: train Random Forest, encode each trace by RF leaf indices, use Hamming-distance k-NN on the leaf code space.
3. **Feature-importance ranking** via RF Gini decrease — used by Walkie-Talkie, WTF-PAD, RegulaTor for defense design.
4. Open-world Bayesian threshold tuning for TPR/FPR trade-off.

## Method
- 175 features computed per trace.
- RF: 1000 trees, default sklearn settings, used solely as a supervised similarity learner.
- Each trace → vector of 1000 leaf IDs.
- k-NN on Hamming distance over the leaf-vector.
- Open-world: threshold on count of monitored class neighbors among k=3.

## Results
| Setting | Acc |
|---|---|
| 100 sites closed-world | 95% |
| 200 sites closed-world | 92% |
| Open-world TPR/FPR | 88% / 0.5% on 9k unmonitored |

Feature-importance top-10 (Gini): cumulative bytes at 50/75% trace position; burst sizes; total outgoing packets; total bytes; ordering of first packets.

## Limitations
- Hand-crafted features hit ceiling; Sirinam 18 DF surpasses with end-to-end learning.
- Concept drift not addressed.
- Wang-Goldberg 16 IEEE S&P shows real-world acc 60–70% (vs 95% lab).
- Open-world threshold tuning is fragile.

## How it informs our protocol design
- **Feature-importance ranking is a defense roadmap** — G6 padding should target top-importance features first (cumulative bytes, burst sizes, ordering of early packets).
- The RF-leaf k-NN architecture is interesting for low-resource attackers — G6 must not assume only DL adversaries.
- 175 features is a useful regression-test feature set: G6 should be evaluated against full k-FP feature space at minimum to detect coverage gaps.

## Open questions
- Why does RF-leaf k-NN beat direct RF prediction? Likely supervised similarity > Gini-tree decision boundary, but unformalized.
- Are there feature interactions the RF importance misses? (Plausible — RF Gini is marginal.)
- Cross-protocol applicability: k-FP on non-Tor (VLESS, Hysteria2) hasn't been systematically evaluated.

## References worth following
- Wang 14 USENIX Sec — competing k-NN approach
- Panchenko 16 NDSS — CUMUL competitor
- Sirinam 18 CCS (DF) — eventually beats k-FP via DL
- Juarez 16 ESORICS (WTF-PAD) — defense designed against k-FP feature ranking
- Cherubin 17 PoPETs — Bayes upper bound on k-FP-like classifiers
