# Automated Website Fingerprinting through Deep Learning
**Venue / Year**: NDSS 2018
**Authors**: Vera Rimmer, Davy Preuveneers, Marc Juarez, Tom Van Goethem, Wouter Joosen
**Read on**: 2026-05-16 (in lesson 10.3)
**Status**: full PDF
**One-line**: Comprehensive evaluation of SDAE/CNN/LSTM on WF; published "AWF" dataset (900 sites × 2500 traces) that became standard benchmark.

## Problem
Abe-Goto 16 hinted NN feasible. What's the SOTA NN architecture for WF, and at what scale?

## Contribution
1. Direct comparison: SDAE / CNN / LSTM on raw direction sequences.
2. AWF dataset publicly released.
3. Closed-world ~97% (CNN), ~96% (LSTM), ~94% (SDAE).

## Method
- Architectures: 3-layer SDAE, 4-layer CNN with MaxPool, 2-layer LSTM.
- Direction sequence length 5000.
- Adam optimizer.

## Results
- 100 sites closed-world: CNN 97%, LSTM 96%, SDAE 94%.
- 900 sites closed-world: CNN 95%, LSTM 92%, SDAE 87%.

## Limitations
- Closed-world only.
- DF (Sirinam 18) shortly after surpassed Rimmer's CNN with deeper architecture.

## How it informs our protocol design
- DL is the de facto WF SOTA family from 2018 onward.
- AWF dataset is benchmark for Proteus eval reproducibility.

## References worth following
- Sirinam 18 CCS (DF) — successor
- Bhat 19 PoPETs (Var-CNN) — data-efficient variant
