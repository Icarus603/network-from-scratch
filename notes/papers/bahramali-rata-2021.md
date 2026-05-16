# Robust Adversarial-Resilient Traffic Analysis (RATA)
**Venue / Year**: IEEE TIFS 2021
**Authors**: Alireza Bahramali, M. Mohammad Bordbar, Amir Houmansadr
**Read on**: 2026-05-16 (in lesson 10.4)
**Status**: full PDF
**One-line**: Robust attacker that withstands adversarial-perturbation defenses (Mockingbird, BLANKET); recovers ~65% accuracy after defense.

## Problem
Adversarial defenses (Mockingbird, BLANKET) drop DF acc to ~30–50%. Are these defenses robust to adaptive attackers using techniques like randomized smoothing?

## Contribution
1. RATA classifier: DF + Gaussian smoothing during training.
2. Multi-channel feature ensemble (direction + size + timing).
3. Recovers 60–70% accuracy against Mockingbird/BLANKET.

## Method
- During training: inject Gaussian noise on input (smoothing).
- Multi-input architecture: direction, size, timing in parallel.
- Augmentation: simulated perturbations during training.

## Results
- vs Mockingbird (defense acc 30%): RATA recovers to 65%.
- vs BLANKET: 60%.

## Limitations
- Doesn't break Surakav as easily (acc still ~50%).
- Increases compute cost moderately.

## How it informs our protocol design
- Adversarial defenses are not silver bullets.
- Proteus evaluation must include RATA-style attacker.

## References worth following
- Hou 19 (Mockingbird) — defense RATA targets
- Nasr 21 (BLANKET) — same
- Sheffey 24 — broader adaptive eval
