# Towards measuring anonymity
**Venue / Year**: PETS 2002
**Authors**: Claudia Diaz, Stefaan Seys, Joris Claessens, Bart Preneel
**Read on**: 2026-05-16 (in lesson 10.1)
**Status**: full PDF
**One-line**: Parallel to Serjantov-Danezis 2002, formalizes anonymity as Shannon entropy of the attacker's posterior over candidate senders/receivers.

## Problem
$|\mathcal{S}|$ (anonymity set size) overstates anonymity when distribution within $\mathcal{S}$ is skewed.

## Contribution
1. **Degree of anonymity** $d = H(\text{posterior}) / H_{\max}$ in $[0, 1]$.
2. Normalized to allow comparison across systems with different $|\mathcal{S}|$.
3. Examples on Crowds and Onion Routing.

## Method
- Define probability distribution over candidate senders given observed traffic.
- Entropy / max-entropy ratio gives normalized anonymity score.

## Results
- Crowds: degree $d$ decreases with attacker presence in path.
- Onion Routing: $d$ depends on path length and adversary control.

## Limitations
- Average-case; doesn't capture worst-case (max-posterior) leakage.

## How it informs our protocol design
- Same as Serjantov-Danezis 2002 (parallel work). Proteus may use normalized degree as comparison metric.

## References worth following
- Serjantov-Danezis 2002 PETS — parallel formulation
- Smith 09 FoSSaCS — QIF generalization
