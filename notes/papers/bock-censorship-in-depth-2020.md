# Detecting and Evading Censorship-in-Depth: Analyzing the Great Firewall of China and Iran
**Venue / Year**: ACM CCS 2020 (Workshop / shorter venue; some references list as workshop)
**Authors**: Kevin Bock, et al. (with Houmansadr group / GFW.report collaborators)
**Read on**: 2026-05-16 (in lessons 11.1, 11.7, 11.12 of Part 11)
**Status**: abstract + key findings; PDF via gfw.report and authors' homepages
**One-line**: Provides systematic measurement of GFW's multi-layer detection apparatus including DPI patterns, active probing pipelines, and adaptive blocking strategies; shows error-pattern oracle attacks against existing proxies.

## Problem
GFW is widely reported to use multiple detection mechanisms in series ("censorship-in-depth"). Bock et al. measure the actual structure and identify exploitable error-pattern oracles in existing circumvention systems.

## Contribution
- Confirms multi-layer detection: passive DPI → active probing → blocking decision.
- Identifies adaptive censor behavior: rules update over time based on observed traffic.
- Catalogs error-pattern oracles in popular circumvention tools (Outline, SS variants).
- Cross-country comparison with Iran's filter.

## Method
- Controlled-deployment measurement from inside/outside GFW boundary.
- Differential probing: vary protocol byte-by-byte and observe block response.
- Side-channel timing analysis.

## Results
- Several common circumvention systems have error-message-pattern oracles (different timeout/error per failure mode).
- Iran has similar but distinct stack.
- Adaptive update windows confirmed.

## Limitations / what they don't solve
- Doesn't reverse-engineer complete GFW state machine.
- Mitigation recommendations are partial.

## How it informs our protocol design
- G6 spec §11.10 enumerates error-pattern oracle resistance: all negative-path responses must be "forward to cover", not differentiated errors.
- G6 spec §7 cover-URL pinning is designed to deny adaptive censor any state in which it can build error-pattern profile.
- G6 design review (lesson 11.12) explicitly references this paper's findings as one of the adversarial reading inputs.

## Open questions
- Does GFW use DL on flow-level features yet? Suspect yes; public evidence partial.
- Adaptive rule update period? Measured at days to weeks.

## References worth following
- gfw.report continuous reports
- Frolov NDSS 2020 (probe-resistant proxy)
- net4people/bbs GitHub
