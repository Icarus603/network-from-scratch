# Cybersecurity in an Era with Quantum Computers: Will We Be Ready? (Mosca's theorem)
**Venue / Year**: IEEE S&P 2018 (and earlier Mosca technical reports 2013-2017)
**Author**: Michele Mosca (Institute for Quantum Computing, University of Waterloo)
**Read on**: 2026-05-16 (in lessons 11.1, 11.4 of Part 11)
**Status**: abstract + Mosca's theorem statement; widely cited public reference
**One-line**: Establishes the "store-now-decrypt-later" (SNDL) threat model: if your data must remain confidential for X years, and large quantum computers arrive in Y years, you must migrate to PQ within Y - X - migration_time years.

## Problem
Quantum computers will eventually break RSA / ECC. When should organizations migrate to post-quantum crypto?

## Contribution
- Formalizes the timeline equation (informally called "Mosca's theorem"):
  ```
  Migration deadline ≤ Y_quantum - X_data_secrecy - T_migration
  ```
  where Y_quantum = years until cryptographically relevant quantum computer, X = years data must stay confidential, T = years to complete migration.
- Argues that for data needing 20+ year secrecy, migration must begin NOW.
- Distinguishes encryption (vulnerable to SNDL) from signatures (post-fact verifiability less affected).

## Contributions to threat modeling
- "Harvest now, decrypt later" / "Store now, decrypt later" adversary class.
- Justifies hybrid (classical + PQ) deployments today even before full PQ confidence.

## Limitations / what they don't solve
- Cannot predict Y_quantum precisely.
- Doesn't address PQ algorithm choice (NIST PQC process did that).

## How it informs our protocol design
- G6 threat model (lesson 11.1) lists C10 = PQ-capable adversary as in-scope **specifically for SNDL**.
- G6 v0.1 §6 commits to hybrid X25519+ML-KEM-768 KEM precisely on this basis.
- G6 v0.1 §11.12 defers PQ signature (Ed25519 only) on the grounds that signature verification can be post-hoc — consistent with Mosca's encryption/signature distinction.

## Open questions
- Refined estimate of Y_quantum: NIST consensus 10-20 years; some experts say sooner.
- Hybrid signature deployment timeline.
- ML-KEM long-term security maturity (algorithm < 10 years old).

## References worth following
- NIST PQC competition rounds (2016-2024)
- CACR (Centre for Applied Cryptographic Research) updates
- IETF CFRG hybrid KE drafts
- IACR ePrint PQ-related
