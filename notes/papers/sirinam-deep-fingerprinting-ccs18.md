# Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning
**Venue / Year**: ACM CCS 2018, pp. 1928–1943
**Authors**: Payap Sirinam (RIT), Mohsen Imani (UT Arlington), Marc Juarez (KU Leuven), Matthew Wright (RIT)
**Read on**: 2026-05-16 (in lessons 9.8, 9.13, 10.3, 10.4)
**Status**: full PDF (`https://arxiv.org/pdf/1801.02265`)
**One-line**: First CNN-based website-fingerprinting attack to break the leading Tor padding defenses (WTF-PAD, Walkie-Talkie partially), reaching ~98 % accuracy on undefended Tor and ~90 % on WTF-PAD — settling that hand-crafted features are obsolete for traffic-shape classification.

## Problem
Pre-2018 website-fingerprinting (WF) attacks on Tor used hand-crafted features (kNN-CUMUL, kFP) and were defeated by Tor's lightweight padding defenses WTF-PAD and Walkie-Talkie. Could deep learning bypass them?

## Contribution
1. A CNN architecture (Deep Fingerprinting, DF) built for ±1-direction packet-sequence input that outperforms all prior WF attacks.
2. Shows WTF-PAD does **not** provide meaningful protection against DL attackers — significant policy implication for Tor.
3. Confirms Walkie-Talkie still resists (drops DF to ~49 %) but at significant overhead cost.

## Method
- **Input representation**: sequence of `±1` per packet (sign = direction, sequence index = arrival order); fixed length 5000 (zero-padded if shorter).
- **Architecture**: stack of 1-D convolutional blocks (filters 32→256, ELU activations, BatchNorm, MaxPool, Dropout) followed by two FC layers → softmax over websites.
- Training: 95-class closed-world (each class = a sensitive website), 800 traces per class.
- Open-world: 95 monitored + 40 000 unmonitored Alexa sites.

## Results
| Setting | DF accuracy | Prior best |
|---|---|---|
| Tor undefended, closed-world | 98.3 % | 91 % (CUMUL) |
| WTF-PAD, closed-world | 90.7 % | <60 % |
| Walkie-Talkie, closed-world | 49.7 % | similar |
| Open-world undefended | precision 0.99, recall 0.94 | — |
| Open-world WTF-PAD | precision 0.96, recall 0.68 | — |

## Limitations / what they don't solve
- Trained per-direction sequence; ignores **timing** features (later Deep-CoFFEA, Tik-Tok, GANDaLF papers add timing).
- Closed-world overestimate of real adversary capability.
- Walkie-Talkie's bandwidth/latency overhead is too high for most deployments.

## How it informs our protocol design
- **The hand-crafted-feature era is over.** Adversary baseline = CNN/Transformer over packet sequence (direction + size + timing).
- **Light defenses (WTF-PAD) fail.** Our protocol must consider stronger defenses (Walkie-Talkie-style burst molding, Trafficsliver, FRONT). Lesson 10.5 enumerates these.
- **Adversary scope**: an entity that can mirror our traffic (GFW does) can run a DF-equivalent classifier offline. Our threat model must account for ~98 %-accuracy traffic-shape attackers, not "DPI-only" attackers.

## Open questions
- Robustness of DF against adversarial-example defenses (cf. lesson 10.4).
- Transferability across Tor versions, browser updates (Tor Browser version-X trained model on version-X+2 traffic).

## References worth following
- Wang, Cai, Nithyanand, Johnson, Goldberg. *Effective Attacks and Provable Defenses for Website Fingerprinting.* USENIX Security 2014 (kNN-WF, the strong pre-DL baseline).
- Juarez et al. *Toward an Efficient Website Fingerprinting Defense.* ESORICS 2016 (WTF-PAD).
- Wang & Goldberg. *Walkie-Talkie.* USENIX Security 2017.
- Rimmer et al. *Automated Website Fingerprinting through Deep Learning.* NDSS 2018 (concurrent DL work, larger model).
