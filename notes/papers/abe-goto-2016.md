# Fingerprinting Attack on Tor Anonymity using Deep Learning
**Venue / Year**: APAN (Asia-Pacific Advanced Network) Research Workshop 2016
**Authors**: Kota Abe, Shigeki Goto
**Read on**: 2026-05-16 (in lesson 10.3)
**Status**: full PDF (workshop)
**One-line**: First neural-network WF attack — stacked denoising autoencoder achieves 88% on 100 Tor sites; the bridge between hand-crafted and DF.

## Problem
Hand-crafted WF reaching 95%; could NNs match or surpass without feature engineering?

## Contribution
1. SDAE (Stacked Denoising Autoencoder) on raw direction sequences.
2. Demonstrate NN approach feasible (~88% acc).
3. Foreshadows AWF / DF.

## Method
- Direction sequence (±1) length 5000.
- SDAE: multiple denoising autoencoders stacked + softmax.

## Results
- 100 sites closed-world: ~88%.

## Limitations
- Workshop paper, limited hyperparameter tuning.
- Below hand-crafted SOTA at the time.

## How it informs our protocol design
- Demonstrates NN feasibility; sets up DF.

## References worth following
- Rimmer 18 NDSS (AWF) — successor at scale
- Sirinam 18 CCS (DF) — modern SOTA
