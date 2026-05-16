# A Critical Evaluation of Website Fingerprinting Attacks
**Venue / Year**: ACM CCS 2014
**Authors**: Marc Juarez, Sadia Afroz, Gunes Acar, Claudia Diaz, Rachel Greenstadt
**Read on**: 2026-05-16 (in lessons 10.2, 10.3, 10.10)
**Status**: full PDF (publicly available)
**One-line**: Identified four core assumptions in WF attack evaluation that, when relaxed to real-world settings, drop attacker accuracy by 20-50 percentage points.

## Problem
By 2014 WF closed-world accuracy was 90%+ on Tor. Field consensus: WF is a real threat. Juarez et al. asked whether the evaluation methodology was actually measuring real-world threat.

## Contribution
Catalogued four "fallacies" of WF evaluation:
1. **Closed-world assumption**: real users visit far more sites than monitored; open-world Bayesian base-rate makes high FPR vs TPR a problem.
2. **Replicability**: training and test traces share platform, network conditions, browser version — real attacker can't match.
3. **Staleness**: training and test typically within hours; sites change over days.
4. **Parsing**: assumes attacker can cleanly segment per-page visits. Real continuous browsing doesn't have clean boundaries.

For each, ran experiments showing 20-50 point accuracy drops when assumption relaxed.

## Method
- Reproduce CUMUL and k-NN attacks on Tor.
- Replicate closed-world results, then modify experiments to relax each assumption.
- Measure accuracy decay.

## Results
| Setup | k-NN Acc | CUMUL Acc |
|---|---|---|
| Lab closed-world | 91% | 92% |
| Open-world (5k unmonitored) | 85% | 88% |
| Staleness 10 days | 60% | 65% |
| Multi-tab parsing | 50% | 55% |
| Cross-platform train/test | 35% | 40% |

## Limitations
- Did not test against future DL attacks (pre-DF).
- Recommendations are diagnostic, not prescriptive about how to fix evaluations.
- The "ideal evaluation" is unspecified — left to subsequent SoKs (Khattak 16, Tschantz 16).

## How it informs our protocol design
- **G6 evaluation must avoid all four fallacies**:
  - Open-world ≥ 100k unmonitored sites
  - Real-world train/test condition mismatch
  - ≥ 30-day staleness gap
  - Multi-tab realistic browsing
- The 20-50% accuracy drop in "real world" gives G6 some natural margin — but doesn't relieve G6 of defense duty since 50% real-world is still too high for state adversary.

## Open questions
- Quantitative threat-model: what's "acceptable" WF accuracy from the user perspective? (Pulls 20 oracle attacks suggest even 50% is sufficient.)
- Concept-drift mitigation strategies (Wang 16 IEEE S&P 跟進)
- "Realistic" methodology consensus: still not standardized in 2024.

## References worth following
- Wang-Goldberg 16 IEEE S&P — extends staleness/realism analysis
- Pulls-Dahlberg 20 PoPETs — oracle attacks boost realistic acc
- Cherubin-Jansen-Troncoso 22 USENIX Sec — online WF realism
- Khattak 16 / Tschantz 16 SoKs — methodology consensus efforts
