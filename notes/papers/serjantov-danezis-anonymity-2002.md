# Towards an Information Theoretic Metric for Anonymity
**Venue / Year**: PETS 2002 (Privacy Enhancing Technologies)
**Authors**: Andrei Serjantov, George Danezis
**Read on**: 2026-05-16 (in lessons 10.1, 10.10)
**Status**: full PDF
**One-line**: Defines anonymity as Shannon entropy of attacker's posterior distribution over possible senders/receivers; supersedes the "anonymity set size" metric.

## Problem
Older anonymity literature used $|\mathcal{S}|$ (anonymity set size) as the metric. But if attacker has unequal posterior over $\mathcal{S}$ (e.g., 99% Alice / 1% others), $|\mathcal{S}|$ overestimates anonymity.

## Contribution
1. Define anonymity as $\mathcal{A}(\mathcal{S}) = -\sum_u p(u) \log_2 p(u)$ where $p$ is attacker's posterior over candidate senders.
2. Show $\mathcal{A} \leq \log_2 |\mathcal{S}|$ with equality iff uniform.
3. Apply to mixnet attacks: traffic-pattern attacks compute attacker's posterior.

## Method
- Treat attacker as Bayesian: $p(u | \text{observation})$.
- Compute entropy of this posterior.
- Compare to $\log_2 |\mathcal{S}|$ upper bound.

## Results
- Diaz et al. 2002 PETS published parallel formulation simultaneously.
- Adopted across anonymous-communication literature.

## Limitations
- Average-case metric; doesn't capture worst-case (max-posterior) leakage.
- Smith 09 QIF later extended to richer adversary models.

## How it informs our protocol design
- G6 evaluation should report anonymity entropy alongside accuracy.
- For "anonymous routing" features (multi-hop), use entropy bound.

## Open questions
- Tightness of entropy bounds in finite-sample real-world settings.

## References worth following
- Diaz et al. 2002 PETS — parallel formulation
- Smith 09 FoSSaCS — QIF generalization
- Chaum 81 — origin
