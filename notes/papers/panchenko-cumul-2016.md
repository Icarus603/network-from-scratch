# Website Fingerprinting at Internet Scale
**Venue / Year**: NDSS 2016
**Authors**: Andriy Panchenko, Fabian Lanze, Jan Pennekamp, Thomas Engel, Andreas Zinnen, Martin Henze, Klaus Wehrle
**Read on**: 2026-05-16 (in lessons 10.2, 10.5)
**Status**: full PDF (publicly available)
**One-line**: Scales WF to ~10^5 sites with CUMUL — a cumulative-bytes representation resampled to 100 dimensions, fed to SVM.

## Problem
Wang 14 hand-crafted features and k-NN don't scale to large datasets; researchers couldn't evaluate WF threat at realistic Internet-scale. Open-world results were thin and dataset sizes ≤ 1000 sites.

## Contribution
1. CUMUL representation: cumulative bytes over trace position, piecewise-linear resampled to 100 dimensions.
2. SVM with RBF kernel on 100-dim CUMUL features.
3. Scale: 100,000-site open-world with TPR ~93% / FPR 0.4%.
4. Public dataset (Alexa Top sites) released.

## Method
- For each Tor cell trace: convert direction sequence ±1 to cumulative sum.
- Linearly interpolate the cumsum curve, sample at 100 equispaced abscissae.
- 100-dim feature vector.
- SVM-RBF, default C/gamma cross-validated.

## Results
| Setting | TPR | FPR |
|---|---|---|
| Closed-world 100 sites | 92% | – |
| Open-world 1k mon / 9k unmon | 95% | 1% |
| Open-world 100k unmonitored | 93% | 0.4% |

## Limitations
- 100-dim resampling drops information (Tik-Tok 20 partially recovers it with timing).
- Lab dataset; concept-drift not addressed (Wang 16 followup).
- Hand-crafted feature ceiling — DF 18 surpasses.

## How it informs our protocol design
- **Cumulative-bytes curve is a top-leakage channel.** G6 must shape this curve to be multi-site indistinguishable.
- Open-world 100k is the right scale for G6 evaluation.
- 100-dim CUMUL feature space is the natural domain for Cherubin 17 Bayes-bound KDE estimation; G6 evaluation should use it.

## Open questions
- Why is 100-dim resampling so effective? What's the right resampling for non-Tor protocols?
- Concept drift on CUMUL features over months — how steep?
- Cross-fingerprint composition (CUMUL + burst features jointly): how does mutual info compose?

## References worth following
- Wang 14 — competing k-NN approach
- Hayes-Danezis 16 (k-FP) — feature-engineering competitor
- Sirinam 18 (DF) — DL surpasses
- Cherubin 17 — uses CUMUL space for Bayes bound
