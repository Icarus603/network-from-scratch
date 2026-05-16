# Geneva: Evolving Censorship Evasion Strategies
**Venue / Year**: ACM CCS 2019, pp. 2199–2214
**Authors**: Kevin Bock, George Hughey, Xiao Qiang, Dave Levin (University of Maryland)
**Read on**: 2026-05-16 (in lessons 9.1, 9.3, 9.14)
**Status**: full PDF (`https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf`); artifact (`https://github.com/Kkevsterrr/geneva`)
**One-line**: A genetic algorithm that evolves packet-manipulation strategies against real censors (GFW, Indian, Kazakh DPI) using only four primitives (drop / tamper / duplicate / fragment), discovering known evasions and many new ones — and **inverting** the usual research workflow by inferring censor mechanics from successful strategies.

## Problem
Manual reverse engineering of how a censor decides to block (e.g. GFW's HTTP keyword block) is slow, brittle, and locality-specific. Can the loop be automated?

## Contribution
1. Geneva: a GA over a forest of strategies, each strategy = a tree of (action, condition) on packet fields. Primitives: drop, tamper (modify header field), duplicate, fragment.
2. End-to-end deployment: hosts a fitness function (= did the censored request complete?) running on real users' machines in China / India / Kazakhstan.
3. **Method inversion**: rather than "study censor → write evasion", Geneva produces working evasions, and the *structure* of winning strategies tells us what the censor checks (TTL, ACK flag, sequence, RST handling, etc.).

## Method
- Strategy DSL: `action_tree ::= action(condition){left_subtree}{right_subtree}`. Conditions on `(direction, protocol, field, value)`.
- Mutation operators: insert/remove action, swap subtrees, mutate condition operands.
- Fitness = (request succeeded ∧ stayed evasive over N retries) − (latency penalty) − (size penalty).
- 4-action primitive set is **complete** in the sense that any flow-rewriting program reduces to a composition of these.

## Results
- Re-derived known evasions: TCB-Teardown (Khattak et al.), IP-fragmentation, multiple-SYN, RST-with-bad-checksum, etc.
- Discovered new GFW evasions: e.g. send `SYN` with payload, send `FIN+payload` before any handshake — GFW's TCB-tracker would tear down its synthetic state, after which subsequent forbidden keywords go through.
- Demonstrated practical browsing: Chrome over Geneva in mainland China, free of keyword-based RST injection.

## Limitations / what they don't solve
- Requires root for raw packet write (NFQUEUE / divert).
- Strategies are GFW-region-specific and can break with GFW updates (the GFW has patched several of these in subsequent years).
- Geneva mostly works against **TCP-layer censors**; payload-layer (DNS, TLS, QUIC) needs follow-up work — see *Bock 2021* (DNS Geneva) and *Wang 2023* (server-side Geneva, `Helping unmodified clients bypass censorship`).

## How it informs our protocol design
- The "fragment / split-SNI" pattern we exploit (lesson 9.5) is essentially a learned Geneva strategy generalised across UDP.
- For our protocol's robustness: even after our cover handshake, we expect the GFW to issue RST/ACK probes mid-stream. Our connection state must be Geneva-robust (i.e. tolerate spurious RSTs / TCB-tear-downs without app-level failure).
- Motivates **co-evolution testing**: a Geneva-style GA against our own implementation as part of CI, to find evasion holes early.

## Open questions
- Can a Geneva-style attacker (rather than evader) discover protocol-detection strategies? The dual problem: evolve probe schedules to maximise mutual information about server identity.
- Adversarial co-training: Geneva-style evader vs. Geneva-style detector → who wins under bounded computation?

## References worth following
- Khattak et al. *Towards Illuminating a Censorship Monitor's Model to Facilitate Evasion.* FOCI 2013 (the manual prior work that Geneva automates).
- Bock et al. *Detecting and Evading Censorship-in-Depth: A case study of Iran's "Protocol Filter".* FOCI 2020.
- Wang, Bock, Levin. *A First Look at Server-Side Blocking of Geographical Regions on the Internet.* IMC 2023.
- Houmansadr et al. *The Parrot is Dead.* IEEE S&P 2013 → [[houmansadr-parrot-is-dead]].
