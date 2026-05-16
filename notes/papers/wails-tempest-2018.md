# Tempest: Temporal Dynamics in Anonymity Systems
**Venue / Year**: PoPETs 2018 issue 3
**Authors**: Ryan Wails, Yixin Sun, Aaron Johnson, Mung Chiang, Prateek Mittal
**Read on**: 2026-05-16 (in lessons 10.7, 10.10, 10.11)
**Status**: full PDF
**One-line**: Long-term temporal patterns (daily/weekly user activity) can fingerprint Tor users; persistence opens long-term identification attack.

## Problem
Most WF research considers single-trace attacks. What if attacker observes user activity over days/weeks?

## Contribution
1. Analyze hourly and daily traffic patterns of Tor users.
2. Show per-user activity histograms are distinctive.
3. Long-term aggregation links sessions across time even when individual sessions are anonymous.

## Method
- Hourly aggregate of cells sent per user.
- 24-hour and 7-day templates.
- Cosine similarity / DTW matching.

## Results
- User-pair linking >90% accuracy at week scale.
- Active during weekday business hours → strong signal.

## Limitations
- Lab-style assumptions of consistent observation.
- User behavior changes break the template.

## How it informs our protocol design
- Proteus cannot fully protect long-term temporal pattern leakage.
- Recommend documenting as out-of-scope in threat model — user behavior is application responsibility.
- Proteus cover-traffic and connection rotation help marginally.

## References worth following
- Khattak 16 / Tschantz 16 SoK
- Pulls 20 (Oracle) — complementary
