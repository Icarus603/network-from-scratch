# Security Arguments for Digital Signatures and Blind Signatures
**Venue / Year**: Journal of Cryptology 2000 (Vol. 13, No. 3)（EUROCRYPT 1996 preliminary "Security Proofs for Signature Schemes"）
**Authors**: David Pointcheval, Jacques Stern
**Read on**: 2026-05-14 (in lesson 3.7)
**Status**: full PDF (`assets/papers/pointcheval-stern-1996.pdf`)
**One-line**: 提出 forking lemma —— ROM-based 對 Schnorr-style signature 的 EUF-CMA reduction 核心 technique；通過 rewinding adversary 在 ROM query 不同 response 提取 sk；所有 Ed25519 / ECDSA / BLS 證明的根技術。

## Problem
1989-1995 Schnorr-family signature 缺 formal EUF-CMA proof under DLP assumption。Existing proofs 都用 strong assumptions (Strong DH, KEA) or limited 對手能力。需要：在 ROM + standard DLP assumption 下證 Schnorr / ElGamal-family 簽章 EUF-CMA。

## Contribution
1. **Forking Lemma**：對 attacker A that makes q hash queries + forges signature, 透過：
   - Run A 一次得 forgery σ_1。
   - Rewind A 到 critical hash query (point at which A 用 hash output to produce forgery)。
   - Re-run A with **different** ROM response。
   - A 可能再產生 σ_2 (relating to σ_1) on same message。
   - From (σ_1, σ_2) extract sk。
2. **Probability bound**: Pr[two valid forgeries on same R] ≥ ε²/(q·X) where ε is forge prob, q hash queries。**Non-tight reduction**——advantage 損失 q factor。
3. **Application**:
   - Schnorr signature EUF-CMA under DLP。
   - ElGamal signature EUF-CMA under DLP (with caveats)。
   - Blind signature scheme proofs (ROS attack-aware版本)。

## Method (forking lemma 草稿)
**Setup**: adversary A on signature scheme with sk x, pk Y, base point G。A runs as black box; reducer B controls ROM oracle (H_table)。

**Phase 1**: B runs A, recording all H queries. A outputs forgery (R*, s*) on message M* with c* = H_table[R*, M*] = "c1_value"。

**Phase 2 (rewind)**: B rewinds A to point where it queried H(R*, M*). B programs new "c2_value" (different from c1_value). A continues; if A produces another forgery (R*, s**) on same M*, then:
```text
s*  = r* + c1 · x  mod q
s** = r* + c2 · x  mod q
⇒ x = (s* - s**) / (c1 - c2)  mod q
```
B 解出 sk → solves DLP.

**Probability** (informal): forking probability ≥ ε²/q where ε = success prob of A, q = hash queries. Reduction loss factor q means non-tight; concrete security ~q reduction.

## Results
- **Schnorr / ECDSA / EdDSA / BLS 證明** 全用此 framework。
- **Pointcheval-Stern bound 後續改進**：
  - Bellare-Neven 2006 multi-sig improved tightness。
  - Brendel-Cremers-Jackson-Zhao 2021 Ed25519-specific tight bound。
- **Forking lemma 被廣泛 generalized** for various Fiat-Shamir signatures。

## Limitations / what they don't solve
- **Non-tight reduction**：q-factor loss。Concrete security for q = 2^60 hash queries → effective security drops by 60 bits。
- **Requires ROM**: not standard-model proof。Canetti-Goldreich-Halevi 1998 critique applies。
- **Hard to use for adaptive multi-user setting**: extension needed。

## How it informs our protocol design
- **G6 spec Security Considerations 必須**：
  - 給 Schnorr-family (Ed25519) 的 concrete bound under DLP + ROM。
  - Cite Brendel-Cremers-Jackson-Zhao 2021 對 Ed25519 tight bound 結果。
  - Reference forking lemma 為 Ed25519 EUF-CMA 證明的根技術。
- **G6 implementation**: hash function 選擇影響 ROM model 的 heuristic strength；用 SHA-256 或 SHA-512（with conservative output truncation）保持 RO-like 行為。

## Open questions
- **Tight standard-model Schnorr proof**: 仍 open。Best known 是 ROM-based forking lemma。
- **Forking 量子 adversary version**: Quantum-rewindable proofs (Unruh 2017+) generalize forking to quantum ROM。
- **Post-quantum forking for ML-DSA**: Dilithium 用 Fiat-Shamir on lattice problem; rewinding proof 結構不同 (no rewinding due to quantum)。

## References worth following
- Pointcheval-Stern *Provably Secure Blind Signature Schemes* (ASIACRYPT 1996)。
- Bellare-Neven *Multi-signatures in the plain public-key model* (CCS 2006) — improved bound。
- Brendel-Cremers-Jackson-Zhao *Provable Security of Ed25519* (IEEE S&P 2021)。
- Unruh *Post-Quantum Security of Fiat-Shamir* (CRYPTO 2017) — quantum forking。
