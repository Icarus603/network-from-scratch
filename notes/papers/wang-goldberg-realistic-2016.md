# On Realistically Attacking Tor with Website Fingerprinting
**Venue / Year**: IEEE Symposium on Security and Privacy 2016
**Authors**: Tao Wang, Ian Goldberg
**Read on**: 2026-05-16 (in lessons 10.3, 10.10)
**Status**: full PDF
**One-line**: Quantifies the "concept drift" / "staleness" cost — WF accuracy degrades from 95% (same-day) to 60% (90-day gap), even without explicit defenses.

## Problem
Juarez 14 identified staleness fallacy qualitatively. Wang-Goldberg 16 quantified it across multiple temporal gaps.

## Contribution
1. Collect Tor traces over 90+ days for 100 monitored sites.
2. Train classifier on day 0, test at days {1, 3, 7, 30, 60, 90}.
3. Document accuracy decay curve.
4. Multi-tab attack experiments showing baseline degradation.

## Method
- Continuous WF data collection: 100 sites, daily browse-and-capture.
- Train k-NN / CUMUL on day-0 traces.
- Test on subsequent days' fresh traces.
- Separately: 2-tab attack simulation.

## Results
| Test gap | k-NN acc | CUMUL acc |
|---|---|---|
| 0 days | 91% | 92% |
| 3 days | 90% | 89% |
| 10 days | 80% | 82% |
| 30 days | 70% | 73% |
| 90 days | 60% | 64% |

Multi-tab (2-page parallel): closed-world acc drops to ~50% from 90%.

## Limitations
- Limited to hand-crafted classifiers; DF concept drift not measured here.
- 100 sites — small relative to modern open-world.
- Doesn't measure attacker retraining cost (which would partially recover acc).

## How it informs our protocol design
- **G6 evaluation must include ≥ 30-day staleness gap** between training and testing data.
- Suggests G6 could leverage drift by frequently rotating wire-format details — increases attacker retraining cost.
- Multi-tab parsing remains an open defense opportunity (GLUE from Gong-Wang 20 addresses).

## Open questions
- DL classifier staleness curve (DF, Tik-Tok)?
- Optimal attacker retraining cadence given staleness?
- Drift sources decomposition: page content change vs CDN change vs network conditions?

## References worth following
- Juarez 14 CCS — qualitative predecessor
- Cherubin 22 USENIX Sec — online realism evaluation
- Sirinam 18 (DF) — DL with implicit drift assumption
- Gong-Wang 20 (GLUE) — multi-tab address
