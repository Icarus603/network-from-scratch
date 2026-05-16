# Improved Website Fingerprinting on Tor
**Venue / Year**: WPES 2013
**Authors**: Tao Wang, Ian Goldberg
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: Improved Tor WF to 80%+ via cell-level (not TLS-record-level) instrumentation and weighted k-NN.

## Problem
Prior Tor WF inferred cells from TLS records imperfectly. What if attacker had cell ground truth?

## Contribution
1. Modified Tor client to log per-cell direction/timing.
2. Weighted k-NN (k=1) on cell-level features.
3. ~80%+ accuracy.

## Method
- Instrument Tor to log per-cell metadata.
- ~150 hand-crafted features over cell sequence.
- k-NN with weighted L1 distance.

## Results
- 80%+ closed-world.
- Precursor to Wang 14 USENIX Sec (3000-feature k-NN).

## Limitations
- Cell-level instrumentation accessible only to research, not real attackers — but their measurements are extrapolatable.

## How it informs our protocol design
- Even with TLS-record-level observation, cell sequence is reconstructable.
- Proteus must shape both cell-level and record-level structure.

## References worth following
- Wang 14 — successor at full scale
