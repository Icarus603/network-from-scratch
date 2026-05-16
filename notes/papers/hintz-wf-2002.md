# Fingerprinting Websites Using Traffic Analysis
**Venue / Year**: PET Workshop 2002 (Privacy Enhancing Technologies)
**Authors**: Andrew Hintz
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: First WF attack — Naïve Bayes on packet-size histograms, 5 HTTPS sites, ~50–60% accuracy.

## Problem
Encrypted web (HTTPS) protects payload but not packet sizes. Can size histograms identify the site visited?

## Contribution
1. First demonstration of WF attack on HTTPS.
2. Naïve Bayes classifier on per-site size histograms.
3. 5 sites × 100 visits dataset.

## Method
- Feature: histogram of packet sizes (25 buckets).
- Classifier: Naïve Bayes assuming independence across buckets.

## Results
- 5 sites: ~50–60% accuracy.
- Demonstrates leakage exists; small scale.

## Limitations
- Tiny dataset.
- No defense analysis.
- Predates Tor era.

## How it informs our protocol design
- Establishes baseline: packet-size leakage is fundamental.

## References worth following
- Liberatore-Levine 06 CCS — successor at scale
