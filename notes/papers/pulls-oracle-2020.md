# Website Fingerprinting with Website Oracles
**Venue / Year**: PoPETs 2020 issue 1
**Authors**: Tobias Pulls, Rasmus Dahlberg
**Read on**: 2026-05-16 (in lessons 10.10, 10.11)
**Status**: full PDF
**One-line**: Augments WF attack with "website oracles" (DNS resolver logs, CT logs, CDN logs) to confirm attacker's classification — drives accuracy close to 100%.

## Problem
WF attacker outputs candidate site list with confidence. In reality, attackers have access to additional information sources ("oracles") to verify candidates. Combining these dramatically reduces false positives.

## Contribution
1. Catalogue oracles: DNS resolver logs, CDN access logs, Certificate Transparency logs, etc.
2. Compose WF classifier output with oracle queries.
3. Empirical evaluation: combined system achieves near-perfect linking.

## Method
- WF on trace → site candidate list with probabilities.
- For each candidate: query oracle to confirm "did this user visit this site at this time?".
- Joint probability → refined identification.

## Results
- Standalone WF: 70% accuracy.
- + DNS oracle: 99%+ accuracy.
- + CT oracle: 95%+ for HTTPS sites issuing certs.

## Limitations
- Requires oracle access (resolver logs not always public).
- Some oracles privacy-policy-controlled.

## How it informs our protocol design
- **Proteus must use DoH (or DoQ) inside the Proteus tunnel** to defeat DNS oracle.
- Avoid identifiers that leak via CT (no per-session certificates issued).
- Inner-app DNS routing through Proteus mandatory.

## Open questions
- Oracle privacy regulations vs attacker access?
- Other oracle sources (browser telemetry, CDN beacons)?

## References worth following
- Khattak 16 / Tschantz 16 SoKs — methodology
- Wang-Goldberg 16 — realism baseline
