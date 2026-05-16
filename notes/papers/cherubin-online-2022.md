# Online Website Fingerprinting: Evaluating Website Fingerprinting Attacks on Tor in the Real World
**Venue / Year**: USENIX Security 2022
**Authors**: Giovanni Cherubin, Rob Jansen, Carmela Troncoso
**Read on**: 2026-05-16 (in lesson 10.10)
**Status**: full PDF
**One-line**: Evaluates WF attacks in realistic online streaming mode (rather than offline complete-trace); shows attacks succeed with partial traces, undermining "wait for trace end" assumption.

## Problem
WF evaluations assume attacker has complete trace before classifying. In real online deployment, attacker would classify in real-time as packets arrive. Does WF work with partial traces?

## Contribution
1. Define online WF setup: classify after every N packets received.
2. Evaluate DF, Tik-Tok, k-FP under this online model.
3. Demonstrate 60% accuracy with first burst, 90% mid-trace.

## Method
- Take undefended Tor traces.
- Truncate at various positions (after first burst, mid-trace, end).
- Re-train and evaluate classifiers per truncation.

## Results
- After first burst (~100 packets): DF achieves 60%, Tik-Tok 70%.
- Mid-trace: 80–90%.
- End: 95%.

## Limitations
- Closed-world only (open-world online classification not addressed).
- Lab dataset; not real-time deployment.
- No defense against online attacks studied.

## How it informs our protocol design
- **Proteus defenses must be active from the first packet**, not just at trace end.
- Front-loaded shaping (FRONT) is essential.
- Trace-end padding alone is insufficient against online attackers.

## Open questions
- Online attack against adversarial defenses?
- Practical real-time deployment cost?
- Trade-off: how much accuracy does online attacker sacrifice for early classification?

## References worth following
- Wang-Goldberg 16 (Realistic) — closed-world realism
- Juarez 14 (Critical) — predecessor methodology critique
- Pulls 20 (Oracle) — orthogonal realism boost
