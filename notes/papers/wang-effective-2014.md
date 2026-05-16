# Effective Attacks and Provable Defenses for Website Fingerprinting
**Venue / Year**: USENIX Security 2014
**Authors**: Tao Wang, Xiang Cai, Rishab Nithyanand, Rob Johnson, Ian Goldberg
**Read on**: 2026-05-16 (in lessons 10.2, 10.5, 10.12)
**Status**: full PDF (publicly available)
**One-line**: Pushed WF closed-world accuracy past 90% with weighted k-NN on cell-level features; first formal "provable defense" framing in the WF literature.

## Problem
Pre-2014 WF used coarse-grained packet-level features (Liberatore-Levine 06, Panchenko 11, Cai 12). Tor's cell-level structure was ignored. Defenses (BuFLO) had no formal guarantees, only empirical reductions.

## Contribution
1. Cell-level data collection via Tor instrumentation (modified Tor client to log cell trace ground truth, eliminating reconstruction noise).
2. >3000 hand-crafted features spanning ordering, burst statistics, cumulative bytes, sub-sequence markers.
3. Weighted-L1 k-NN classifier with feature weights learned via RFE (recursive feature elimination).
4. Closed-world 91% on 100 Tor sites; open-world TPR ~85% with FPR 2%.
5. **"Provable defense" framework**: defenses with formal upper bound on attacker accuracy for a specific feature class. Tamaraw-precursor defense given with bound (loose).

## Method
- Features grouped: (1) packet counts (in/out totals), (2) burst structure (sizes, count), (3) packet ordering numerical features, (4) cumulative byte amounts at sub-intervals, (5) initial packet markers.
- RFE prunes ~10000 raw candidates to ~3000 informative ones.
- Distance: weighted-L1 with per-feature scale.
- k-NN with k = 5, weighted voting.

## Results
| Setting | Acc |
|---|---|
| 100 sites closed-world | 91% |
| 5000 unmonitored open-world TPR | 85% at FPR 2% |
| Defended (BuFLO) | 12% |
| Defended (proposed quantized-cell defense) | ~10% (provable bound 11%) |

## Limitations
- Provable bound holds only for defined feature class. Sirinam 18 DF used raw direction sequence (outside the feature class) and reaches 98% on undefended; bound doesn't apply.
- Feature engineering complexity makes the work non-scalable to 100k sites without curation.
- Single-tab assumption.

## How it informs our protocol design
- Demonstrates how easily a feature-class-specific provable bound breaks under DL — G6 must use Bayes-optimal upper bounds (Cherubin 17), not feature-class-specific bounds.
- Shows the importance of explicit feature taxonomy when claiming "provable" — G6 spec must define precisely which adversary class its bounds cover.
- The cumulative-byte feature (later formalized as CUMUL by Panchenko 16) is one of the most consistent leakage channels — G6 must address it.

## Open questions
- What's the right feature class to make Wang-14 style proofs DL-resistant? (Cherubin 17 abandoned feature class entirely.)
- Multi-visit aggregation: Wang 14's bound is single-visit; daily leakage composition unclear.

## References worth following
- Cai 12 CCS (Touching from a Distance) — predecessor
- Panchenko 16 NDSS (CUMUL) — feature-engineering followup
- Hayes-Danezis 16 USENIX Sec (k-FP) — feature-engineering peak
- Sirinam 18 CCS (DF) — invalidated the feature-class bound
- Cherubin 17 PoPETs (Bayes bound) — successor framework
