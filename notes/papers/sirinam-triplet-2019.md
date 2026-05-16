# Triplet Fingerprinting: More Practical and Portable Website Fingerprinting with N-Shot Learning
**Venue / Year**: ACM CCS 2019
**Authors**: Payap Sirinam, Nate Mathews, Mohammad Saidur Rahman, Matthew Wright
**Read on**: 2026-05-16 (in lesson 10.3)
**Status**: full PDF
**One-line**: Metric-learning WF: train embedding via triplet loss; new sites need only N≤5 samples for k-NN classification.

## Problem
DF/Var-CNN need many samples per site. For attacker adapting to new sites or concept drift, training is expensive. Could metric learning enable fast adaptation?

## Contribution
1. Embed trace via triplet-loss CNN: anchor, positive (same site), negative (different) → embedding metric.
2. After training, new site requires 1–5 reference embeddings.
3. K-NN on embedding metric.

## Method
- DF-like CNN as feature extractor.
- Triplet loss: $\max(0, \|f(a) - f(p)\| - \|f(a) - f(n)\| + \alpha)$.
- Train on large dataset; freeze embedder.
- Per-deployment: collect ≤5 reference traces per target site.

## Results
- N=5 shot: 95% accuracy on new sites.
- N=1 shot: ~85%.
- Concept-drift resistant: rebuilding catalog is cheap.

## Limitations
- Embedder still requires significant pretraining.
- Site representation can drift; periodic refresh needed.

## How it informs our protocol design
- Adversary can quickly expand to new monitored sites — Proteus cannot assume "obscure sites" are safe.
- Concept-drift mitigation via cheap reference re-collection.

## References worth following
- Sirinam 18 (DF)
- Wang-Goldberg 16 — drift quantification
