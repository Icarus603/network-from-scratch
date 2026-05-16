# FS-Net: A Flow Sequence Network For Encrypted Traffic Classification
**Venue / Year**: IEEE INFOCOM 2019
**Authors**: Chang Liu, Longtao He, Gang Xiong, Zigang Cao, Zhen Li
**Read on**: 2026-05-16 (in lesson 10.8)
**Status**: full PDF
**One-line**: Deep flow-sequence classifier (BiGRU + auto-encoder) for encrypted traffic categorization; 90%+ accuracy on app categories.

## Problem
Existing encrypted-traffic classifiers used hand-crafted features. Could DL approaches generalize across app categories?

## Contribution
1. End-to-end flow-sequence encoder using BiGRU.
2. Auto-encoder reconstruction loss for representation quality.
3. Multi-class app-category classification.

## Method
- Per flow: sequence of (packet size, direction).
- BiGRU encoder.
- Decoder reconstructs packet-size sequence (auxiliary task).
- Classification head.

## Results
- App-category accuracy 90%+.
- Outperforms hand-crafted features.

## Limitations
- Per-flow not per-session.
- App categories (browsing/streaming/chat) coarser than per-app.

## How it informs our protocol design
- Proteus tunneling normalizes inner-app flow patterns at the TLS-record level; FS-Net-style attack would still see normalized flow.
- Per-category fingerprinting threat acknowledged.

## References worth following
- AppScanner (Taylor 16) — predecessor
- FlowPrint (van Ede 20) — semi-supervised
