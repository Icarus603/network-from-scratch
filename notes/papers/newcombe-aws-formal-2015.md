# How Amazon Web Services Uses Formal Methods
**Venue / Year**: Communications of the ACM, April 2015 (vol 58 no 4)
**Authors**: Chris Newcombe, Tim Rath, Fan Zhang, Bogdan Munteanu, Marc Brooker, Michael Deardeuff
**Read on**: 2026-05-16 (in lessons 11.2, 11.9 of Part 11)
**Status**: abstract + key conclusions; CACM open-access link
**One-line**: Industrial case study showing TLA+ catches design bugs in distributed-storage protocols (S3, DynamoDB) that would have been months of debugging post-deployment; argues formal methods scale to industrial spec.

## Problem
AWS engineers shipped distributed-storage protocols (S3, DynamoDB) and routinely found post-deploy bugs that surfaced only at certain race conditions. Question: can formal methods (TLA+) help catch these before deploy?

## Contribution
- Demonstrates TLA+ used pragmatically at AWS scale (~10 engineers across multiple services).
- Concrete bugs caught:
  - S3's bucket-versioning protocol race that would have caused data loss at 1-in-10⁹ scale.
  - DynamoDB's replicated transactions protocol bug that allowed stale reads.
- Argues TLC model checker is sufficient for many protocols (not full theorem prover).
- Cost analysis: ~1 engineer-week per protocol for initial TLA+ spec; subsequent updates cheap.

## Method
- Senior engineers spec'd protocols in TLA+ before/during/after coding.
- TLC model checker run on small instances.
- Bugs found via counter-example traces.

## Results
- Multiple bugs caught that classical testing missed.
- Engineers report TLA+ "forced careful thinking about state transitions".
- AWS continues to use TLA+ as 2015-2020+.

## Limitations / what they don't solve
- TLC model checking ≠ full theorem proof; assumes small finite model represents larger reality.
- Steep learning curve for engineers.
- Doesn't address implementation bugs (only spec bugs).

## How it informs our protocol design
- G6 lesson 11.9 cites this as industry validation that TLA+ is worth the engineering investment.
- G6Handshake.tla follows the AWS pattern: small model, invariants, TLC.
- Engineering discipline: write spec in TLA+ before coding (G6 v0.1 first, Part 12 impl second).

## Open questions
- TLA+ industry adoption rate beyond AWS / Microsoft / Oracle?
- Can TLA+ specs be auto-generated from implementation? Active research.
- Composition of TLA+ + crypto verification (ProVerif/Tamarin)? Manual today.

## References worth following
- Lamport, *Specifying Systems* (TLA+ textbook)
- Hawblitzel OSDI 2014 (Ironclad: spec-to-impl chain)
- AWS internal blog posts (some public) on TLA+ adoption
