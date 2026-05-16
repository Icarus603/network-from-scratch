# Statistical Measurement of Information Leakage
**Venue / Year**: TACAS 2010
**Authors**: Konstantinos Chatzikokolakis, Tom Chothia, Apratim Guha
**Read on**: 2026-05-16 (in lessons 10.1, 10.12)
**Status**: full PDF
**One-line**: Statistical estimation procedure for Shannon mutual info and capacity from finite samples, with confidence intervals.

## Problem
Information-theoretic measures are defined over distributions; in practice we only have samples. How to estimate $I(X; Y)$ and capacity from data with statistical guarantees?

## Contribution
1. Bias-corrected estimator for mutual info from joint samples.
2. Asymptotic confidence intervals via bootstrap.
3. Application to information-leakage analysis tools.

## Method
- Estimate $\hat{H}(X), \hat{H}(Y), \hat{H}(X, Y)$ via empirical frequencies + correction.
- Bias correction for finite samples (Miller-Madow style).
- Bootstrap for confidence interval.

## Results
- Tighter bounds than naive plug-in estimator.
- Public tool implementations.

## Limitations
- Requires discrete or discretized observations.
- High-dim sequences not directly addressable.

## How it informs our protocol design
- G6 capacity estimation in Part 12 evaluation uses this approach.
- Bootstrap CI provides honest reporting.

## References worth following
- Cherubin 17 PoPETs — applies to WF
- Smith 09 QIF — framework basis
