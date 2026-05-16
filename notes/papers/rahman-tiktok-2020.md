# Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks
**Venue / Year**: PoPETs 2020 issue 3
**Authors**: Mohammad Saidur Rahman, Payap Sirinam, Nate Mathews, Kantha Girish Gangadhara, Matthew Wright
**Read on**: 2026-05-16 (in lesson 10.3, 10.5)
**Status**: full PDF (publicly available)
**One-line**: Adds packet timing to DF via `direction × log(time)` representation, breaking Walkie-Talkie and pushing closed-world accuracy to 99.5%.

## Problem
DF (Sirinam 18) used only direction sequence. Defenses like Walkie-Talkie reduced DF to ~50% by making direction patterns indistinguishable for paired sites. But timing was never shaped. If timing carries enough info, defenses ignoring timing should still leak.

## Contribution
1. New feature representation: per-cell `d_i · log(t_i + 1)` combining direction and timing in a single 1D channel.
2. Same DF-style CNN architecture; only input representation differs.
3. Demonstrates Walkie-Talkie inadequate (acc 81%) and even Front (Gong-Wang 20) struggles (88%).

## Method
- Input: vector of `d_i · log(t_i + 1)` for each cell, length 5000.
- Direction $d_i \in \{+1, -1\}$, $t_i$ = time since first cell.
- Log scaling allows network-condition variation to be normalized.
- Same architecture as DF (4-block 1D CNN, ELU activation, MaxPool stride 4, Dropout).

## Results
| Defense | Tik-Tok | DF | Front | k-FP |
|---|---|---|---|---|
| Undefended | 99.5% | 98.3% | – | 95% |
| WTF-PAD | 98.4% | 90.7% | – | 65% |
| Walkie-Talkie | 81.0% | 49.7% | – | 20% |
| Front | 88.2% | 79.1% | – | – |

## Limitations
- Same closed-world / data hunger concerns as DF.
- Doesn't address open-world rigorously beyond previous WF papers.
- Doesn't formally bound information leakage — purely empirical.
- Wang–Goldberg 16 concept-drift concerns still apply.

## How it informs our protocol design
- **Timing is a first-class WF channel — Proteus must shape timing alongside direction.**
- Confirms Walkie-Talkie-style supersequence defense is insufficient since it only covers direction.
- The `log(time)` normalization motivates Proteus to use real-system timing patterns rather than synthetic constant rates (constant rates would saturate the log channel and stand out).
- Establishes Tik-Tok as the WF attacker baseline Proteus must beat. DF alone is no longer sufficient evidence.

## Open questions
- What's the irreducible timing leakage given physical RTT variability? Can RegulaTor envelope close all of it?
- Tik-Tok against Surakav (Gong 22): published as 36% — but that's in benign setting. Adaptive Tik-Tok with retraining: unknown.
- Streaming / online variant of Tik-Tok: does Cherubin 22's online-WF setup apply?

## References worth following
- Sirinam 18 CCS (DF) — direct predecessor
- Bhat 19 PoPETs (Var-CNN) — alternative architecture with timing
- Cherubin 17 PoPETs (Bayes bound) — for theoretical ceiling
- Gong-Wang 20 USENIX Sec (Front) — defense Tik-Tok evaluates against
- Wang-Goldberg 17 USENIX Sec (Walkie-Talkie) — defense Tik-Tok breaks
