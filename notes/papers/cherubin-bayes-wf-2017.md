# Bayes, Not Naïve: Security Bounds on Website Fingerprinting Defenses
**Venue / Year**: PoPETs (PETS) 2017 issue 4
**Authors**: Giovanni Cherubin
**Read on**: 2026-05-16 (in lessons 10.1, 10.3, 10.12)
**Status**: full PDF (publicly available)
**One-line**: Gives a classifier-agnostic upper bound on attacker accuracy for any WF defense via Bayes-optimal classifier estimation.

## Problem
WF defense evaluation routinely reports "accuracy of attack X drops from 95% to 30% under defense Y" — but the bound is specific to attack X. A new attack (DF 18, Tik-Tok 20) routinely shatters such bounds. Defense designers lack a way to certify "no attack can exceed Z%".

## Contribution
Apply Smith 09 QIF + Bayes-optimal classifier theory to WF:
1. For any (defended) dataset, derive an upper bound on attacker classification accuracy that holds for *any* classifier including deep learning.
2. Provide a kernel-density-estimator-based method to compute the bound from a labeled dataset.
3. Demonstrate the bound is non-trivial on Tor traces under WTF-PAD and BuFLO.

## Method
- Bayes-optimal classifier: $f^*(y) = \arg\max_x P(X=x | Y=y)$ with $\text{acc}^* = E_Y[\max_x P(X=x | Y=y)]$.
- $\text{acc}^*$ estimated via KDE on $(X, Y)$ training pairs, with $Y$ = feature vector (CUMUL features used in paper).
- Provides confidence intervals on the estimate using bootstrap.

## Results
- Undefended Wang 14 Tor: $\hat{\text{acc}}^* \approx 96\%$. Real DF (Sirinam 18) achieves 98% — close to bound (sample-size bias).
- BuFLO defended: $\hat{\text{acc}}^* \approx 35\%$. Actual DF 60% — bound holds but loose.
- WTF-PAD: $\hat{\text{acc}}^* \approx 80\%$ — predicted that WTF-PAD wouldn't survive DL (proven true by Sirinam 18 next year).

## Limitations
- KDE estimator quality depends on feature representation chosen; raw sequences not directly amenable.
- Finite-sample bias: bound can underestimate true attacker accuracy when training set is small.
- Closed-world assumption; open-world version not in this paper.
- Only single-visit; doesn't compose tightly across multiple user visits.

## How it informs our protocol design
- **Proteus evaluation must report $\hat{\text{acc}}^*$** alongside specific-attack accuracies. This is the "classifier-agnostic" headline number.
- Allows Proteus to claim "no attack can exceed X%" with statistical backing.
- Suggests choice of feature representation (CUMUL space) for evaluation simulator.
- Pairs with QIF g-leakage table (Smith 09) for richer reporting.

## Open questions
- Can the estimator be improved to give tighter bounds on raw sequence representations (avoid lossy hand-crafted feature reduction)?
- Composition over multiple visits: does the bound add linearly? If not, what's the form?
- Computational restrictions: Bayes-optimal assumes unbounded compute; what's the "computational Bayes" version?

## References worth following
- Smith 2009 FoSSaCS — QIF foundation
- Chatzikokolakis 2010 TACAS — capacity estimation
- Wang 2014 USENIX Sec — "provable defense" precursor
- Sirinam 2018 CCS — empirical demonstration that Cherubin's predictions held
- Stuart 24 PoPETs (forthcoming/tentative) — Maybenot auto-bound estimation
