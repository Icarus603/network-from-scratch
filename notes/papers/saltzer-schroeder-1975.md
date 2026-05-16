# The Protection of Information in Computer Systems
**Venue / Year**: Proceedings of the IEEE, vol 63 no 9, Sep 1975
**Authors**: Jerome H. Saltzer, Michael D. Schroeder
**Read on**: 2026-05-16 (in lesson 11.1 of Part 11)
**Status**: foundational paper; full text widely available (MIT.edu open access)
**One-line**: Defines the 8 classical security design principles (least privilege, fail-safe defaults, complete mediation, etc.) — still the foundational checklist for any security-system design 50 years later.

## Problem
1970s: nascent computer security had no engineering principles. Saltzer & Schroeder distill working practice into design rules.

## Contribution
- The 8 principles:
  1. **Economy of mechanism** — keep it simple.
  2. **Fail-safe defaults** — default deny.
  3. **Complete mediation** — check every access.
  4. **Open design** — security via mechanism, not obscurity.
  5. **Separation of privilege** — multiple keys, not master key.
  6. **Least privilege** — programs / users with minimum needed rights.
  7. **Least common mechanism** — minimize shared state.
  8. **Psychological acceptability** — users will route around bad UX.
- These have survived as the canonical reference list for 50+ years.

## How it informs our protocol design
- Proteus's "silent drop / forward-to-cover" pattern: fail-safe default.
- Proteus's spec-public + crypto-standard: open design.
- Proteus's per-session ephemeral + KEYUPDATE rotation: least common mechanism + privilege separation across time.
- Proteus's BCP-14-strict normative MUST/SHOULD/MAY: complete mediation (explicit verification at every gate).

## References worth following
- NIST SP 800-160 (Systems Security Engineering)
- Anderson, *Security Engineering* 3rd ed. (modern extension)
- Saltzer-Reed-Clark "End-to-end arguments" (later companion principle)
