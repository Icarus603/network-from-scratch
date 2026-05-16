# Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning
**Venue / Year**: ACM CCS 2018
**Authors**: Payap Sirinam, Mohsen Imani, Marc Juarez, Matthew Wright
**Read on**: 2026-05-16 (in lessons 11.2, 11.3, 11.12 of Part 11)
**Status**: abstract + headline results from public CCS proceedings (not yet fetched as PDF)
**One-line**: Shows 1D-CNN website-fingerprinting classifier achieves 98% accuracy on undefended Tor traffic and substantially undermines previously claimed WTF-PAD / Walkie-Talkie defenses, raising the WF defense bar.

## Problem
Earlier WF defenses (BuFLO, Tamaraw, WTF-PAD, Walkie-Talkie) were evaluated against classical ML classifiers (SVMs, k-NN, Random Forests). Defenses claimed acceptable error under those. Sirinam et al. ask: do these defenses survive a deep-learning classifier?

## Contribution
- Designs a 1D-CNN architecture tuned for packet-direction sequences (Tor cell sequences).
- Applies to:
  - Undefended Tor traffic: 98.3% closed-world accuracy.
  - Walkie-Talkie defense (Wang-Goldberg 2017): drops to 49% — still significant.
  - WTF-PAD (Juarez et al. 2016): drops to ~90% — WTF-PAD largely useless against DL.
- Shows that defenses must contend with adversarial deep learning, not just classical ML.

## Method
- 1D-CNN, ~7 layers, on packet-direction time series.
- Closed-world (N=95) and open-world experiments.
- Includes data augmentation and dropout.

## Results
- Major findings reshape WF defense field: defenses calibrated on classical classifiers are not robust against DL.
- Even Tamaraw (most aggressive padding, ~120% overhead) only forces DL accuracy to ~30% — non-zero.

## Limitations / what they don't solve
- Closed-world somewhat artificial; open-world results less impressive but still actionable.
- Doesn't extend to non-Tor traffic.
- Doesn't address multi-flow attacks (later Wang-Hopper 2019).

## How it informs our protocol design
- Proteus CAR-1 reference attacker `A_dl` is modeled after this paper's 1D-CNN architecture.
- ε target (≤ 0.20 against A_dl) calibrated to match what Tamaraw + similar achieve.
- Proteus's per-cell 1280B padding + cover-IAT shaping is designed to be at least as strong as Tamaraw against this classifier class.
- Empirical evaluation in Part 12.10 will train a 1D-CNN per this paper as one of the reference attackers.

## Open questions
- Lower bound on DL classifier accuracy under any padding budget? Open.
- Transferability of defenses across DL architectures (CNN → Transformer → BiLSTM)? Partial answers.

## References worth following
- Wang-Goldberg WPES 2013 (foundational WF classifier)
- Cai et al. CCS 2014 (Tamaraw)
- Juarez et al. NDSS 2016 (WTF-PAD)
- Wang-Hopper PoPETs 2019 (multi-flow defense)
- Rahman et al. PoPETs 2019 (Mockingbird, adversarial defense)
