# Threat Modeling: Designing for Security
**Venue / Year**: Wiley, 2014 (book)
**Author**: Adam Shostack (Microsoft; later independent)
**Read on**: 2026-05-16 (in lesson 11.1 of Part 11)
**Status**: textbook; not fetched as PDF (copyright); referenced from public materials
**One-line**: Standard industry textbook on STRIDE-based threat modeling; provides methodology to enumerate threats, derive defenses, and document residual risk.

## Problem
Industry needs a repeatable methodology for early-stage security analysis. Ad-hoc "what could go wrong" sessions miss important threats.

## Contribution
- Codifies STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.
- Provides templates for capability matrix, attack tree, residual risk.
- Argues threat modeling should happen at design time, not post-deploy.

## Method
- Decompose system → identify trust boundaries → list assets → apply STRIDE per boundary.
- Mitigations: redesign, transfer, accept, eliminate.

## Limitations / what they don't solve
- STRIDE doesn't cover all attack classes (e.g., side-channel, supply chain).
- Not formal; relies on human judgment.

## How it informs our protocol design
- G6 lesson 11.1 §3 uses STRIDE classification directly.
- Capability matrix structure derived from Shostack-style enumeration.
- Residual-risk listing in 11.12 and spec §11.16 follows Shostack template.

## References worth following
- NIST SP 800-30 (Risk Assessment)
- NIST SP 800-37 (Risk Management Framework)
- MITRE ATT&CK Framework (post-deploy threat tracking)
