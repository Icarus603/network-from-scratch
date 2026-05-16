# Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning
**Venue / Year**: ACM CCS 2018
**Authors**: Payap Sirinam, Mohsen Imani, Marc Juarez, Matthew Wright
**Read on**: 2026-05-16 (in lesson 10.3, 10.5, 10.12)
**Status**: full PDF (publicly available)
**One-line**: A deep CNN attack that destroyed every WF defense believed safe at the time (WTF-PAD, Walkie-Talkie partial), establishing DL as the dominant WF attack family.

## Problem
2016 hand-crafted-feature attacks (k-NN, CUMUL, k-FP) achieved ~95% on undefended Tor but were defeatable by lightweight defenses (WTF-PAD: ↓60%, Walkie-Talkie: ↓20%). The field assumed these defenses were "safe enough". Sirinam et al. tested whether deep learning would change this.

## Contribution
1. Designed DF — a 4-block 1D CNN trained on raw cell direction sequences (length 5000). No feature engineering.
2. Demonstrated WTF-PAD provides essentially no protection against DF (acc 90.7%).
3. Demonstrated Walkie-Talkie still helps but accuracy ~50% (random guess between 2 supersequence-paired sites).
4. Open-world: TPR 0.98 / FPR 0.02.

## Method
- Input: ±1 direction sequence per cell, padded/truncated to 5000.
- Architecture: 4 Conv blocks, each [Conv1D + BatchNorm + ELU + Conv1D + BN + ELU + MaxPool(stride=4) + Dropout]. Filter counts: 32, 64, 128, 256. Kernel size 8.
- 2 FC layers (512, then N_classes). Softmax.
- Optimizer: Adamax, LR 0.002, batch 128, 30 epochs.
- Loss: categorical cross-entropy.

## Results
| dataset | DF acc | best hand-crafted |
|---|---|---|
| Undefended (95 sites, Wang 14) | 98.3% | 95% (k-FP) |
| WTF-PAD defended | 90.7% | 60% |
| Walkie-Talkie | 49.7% | <20% |
| Open-world 95 monitored vs 9k unmonitored | TPR 0.98 / FPR 0.02 | TPR 0.88 / FPR 0.05 |

## Limitations
- Closed-world primary metric; Wang 16 IEEE S&P shortly after pointed out real-world drift drops acc 20–30%.
- Single-tab assumption; multi-tab not addressed.
- Only direction features; Tik-Tok (Rahman 20) showed adding timing further boosts.
- Requires 800+ traces/site for training; data-hungry compared to Var-CNN.

## How it informs our protocol design
- **DF is the minimum WF adversary baseline Proteus must defend against.**
- Demonstrates that "marginal statistic shaping" (WTF-PAD) is insufficient — sequence structure leaks.
- Direction sequence alone gives ~98% accuracy → Proteus must shape direction sequence itself, not just sizes/timing.
- Open-world results inform Proteus evaluation methodology — use realistic 9k+ unmonitored set.

## Open questions
- Closed-world ceiling: is 98% the Bayes-optimal accuracy or just DF's? (Cherubin 17 says ~96%, so DF ≈ optimal under their KDE estimator).
- Robustness against adversarial defenses (Mockingbird 19, Surakav 22) — empirically degrades to ~30%.
- Cross-protocol transfer: DF trained on Tor; does it work on Shadowsocks / VLESS? Limited literature.

## References worth following
- Rimmer 2018 NDSS (AWF) — DF's immediate predecessor
- Rahman 2020 PoPETs (Tik-Tok) — adds timing
- Bhat 2019 PoPETs (Var-CNN) — data-efficient variant
- Hou 2019 (Mockingbird) — adversarial defense against DF
- Sirinam 2019 CCS (Triplet) — same group's metric learning follow-up
