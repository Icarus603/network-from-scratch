# On the Foundations of Quantitative Information Flow
**Venue / Year**: FoSSaCS 2009 (Foundations of Software Science and Computational Structures)
**Authors**: Geoffrey Smith
**Read on**: 2026-05-16 (in lessons 10.1, 10.12)
**Status**: full PDF (Springer)
**One-line**: Foundational paper for quantitative information flow: defines $g$-leakage and connects min-entropy / Bayes-optimal classifier accuracy / gain-function adversaries.

## Problem
Shannon mutual info measures average leakage; doesn't capture worst-case (most-likely-guess) or task-specific (different attacker goals) leakage. Need a generalized framework.

## Contribution
1. Define **gain function** $g(x, y) \in [0, 1]$: how much attacker "wins" when system value is $x$ and guess is $y$.
2. Vulnerability $V_g(X) = E[\max_y g(X, y)]$ and posterior $V_g(X|Y)$.
3. $g$-leakage $L_g = \log_2 (V_g(X|Y) / V_g(X))$.
4. Show Shannon mutual info corresponds to specific $g$; min-entropy to another.

## Method
- Formal definitions in language of probability and information theory.
- Examples: password guessing, classifier accuracy, partial-information leakage.

## Results
- $g$-leakage = Shannon when $g$ is appropriate weighted-log.
- $g$-leakage = min-entropy leakage when $g(x, y) = [x == y]$ (exact match).
- Modular framework for richer adversary models.

## Limitations
- Doesn't directly give estimation procedures (Chatzikokolakis 10 provides).
- Composition results limited.

## How it informs our protocol design
- **Proteus evaluation should report multiple $g$-leakages** (exact site, top-5, topic-class) for richer leakage picture.
- Smith 09 framework is the right language for Proteus quantitative provability claims.

## Open questions
- Tight composition bounds for $g$-leakage across multiple observations.
- Sample complexity of $g$-leakage estimation.

## References worth following
- Chatzikokolakis 10 TACAS — capacity estimation
- Cherubin 17 PoPETs — applies to WF
- Alvim, Andrés, Chatzikokolakis, Palamidessi book on QIF
