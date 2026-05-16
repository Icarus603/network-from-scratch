# Var-CNN: A Data-Efficient Website Fingerprinting Attack Based on Deep Learning
**Venue / Year**: PoPETs 2019
**Authors**: Sanjit Bhat, David Lu, Albert Kwon, Srinivas Devadas
**Read on**: 2026-05-16 (in lesson 10.3)
**Status**: full PDF
**One-line**: Data-efficient WF DL using ResNet-style dilated convolutions; matches DF accuracy with 10× fewer training traces.

## Problem
DF requires 1000 traces/site. For attackers retraining on fresh data (concept drift), this is costly. Could less-data architecture work?

## Contribution
1. Dilated 1D convolutions for wider receptive field with fewer parameters.
2. ResNet-style skip connections for stable training.
3. Multi-input architecture: direction + timing in parallel branches.
4. 95% acc with 100 traces/site.

## Method
- Two parallel sub-networks: one for direction, one for timing.
- Each sub-network: dilated ResNet with 1D conv blocks.
- Fusion FC layer combines representations.

## Results
- 100 traces/site closed-world: 95% (DF 90.6% at same data).
- ROC AUC 0.99 open-world.

## Limitations
- Multi-branch architecture more complex than DF.
- Timing channel exploited; later Tik-Tok formalizes it.

## How it informs our protocol design
- Attacker can deploy with low data → G6 cannot rely on attacker's slow retraining.
- Timing channel critical; G6 timing module mandatory.

## References worth following
- Sirinam 18 (DF)
- Rahman 20 (Tik-Tok) — more thorough timing exploit
