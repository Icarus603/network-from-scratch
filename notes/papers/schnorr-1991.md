# Efficient Signature Generation by Smart Cards
**Venue / Year**: Journal of Cryptology, Vol. 4, No. 3, 1991（CRYPTO 1989 preliminary）
**Authors**: Claus-Peter Schnorr
**Read on**: 2026-05-14 (in lesson 3.7)
**Status**: full PDF (`assets/papers/schnorr-1991.pdf`)
**One-line**: Schnorr signature 的 paper——把 Schnorr identification protocol 用 Fiat-Shamir 變 non-interactive signature；structure 比 DSA / ECDSA 更簡潔、有 tight EUF-CMA reduction、aggregation-friendly；Ed25519 是 deterministic Schnorr，Bitcoin BIP-340 Taproot 採用。

## Problem
1989-1991 主流數位簽章：RSA、ElGamal。兩者都有缺陷：
- RSA 大 (1024+ bit)、慢 (^d mod n)。
- ElGamal 簽章 size ~2x of modulus、verification 需要 modular inverse、缺 tight reduction。

需要：short, fast, well-analyzed signature。Schnorr 從 his earlier identification protocol 出發，用 Fiat-Shamir 把 interactive ID 變 signature。

## Contribution
1. **Schnorr Identification Protocol**:
   ```
   sk = x, pk = Y = xG
   P: r ← random; R = rG; send R
   V: c ← random; send c
   P: s = r + cx mod q; send s
   V: check sG == R + cY
   ```
2. **Fiat-Shamir variant for signature**:
   ```
   Sign(sk, M):
       r ← random
       R = rG
       c = H(R ‖ M)
       s = r + cx mod q
       return (R, s)  or (c, s)
   Verify(pk, M, (R, s)):
       check sG == R + H(R ‖ M)·Y
   ```
3. **Short signature**: (c, s) 兩個 scalar mod q → 約 2|q| bits。對 256-bit DLP group，512-bit total。
4. **Tight EUF-CMA reduction** (Pointcheval-Stern 1996 forking lemma)：assume A breaks Schnorr-Sig in ROM, construct B solving DLP via rewinding A twice.
5. **Aggregation-friendly**: linear in (r, x) → n-of-n threshold + multi-sig 自然存在 (MuSig, FROST 等)。

## Method
**Setup**: Cyclic group G of prime order q, generator G_elem.

**KGen**:
```text
x ← random in [1, q-1]
Y = x · G_elem
return (sk=x, pk=Y)
```

**Sign(sk = x, M)**:
```text
r ← random in [1, q-1]
R = r · G_elem
c = H(encode(R) ‖ M) mod q
s = (r + c · x) mod q
return (R, s)    or compressed (c, s)
```

**Verify(pk = Y, M, σ = (R, s))**:
```text
c = H(encode(R) ‖ M) mod q
check s · G_elem == R + c · Y    (group equation)
return valid iff equation holds
```

**EUF-CMA 證明 sketch** (Pointcheval-Stern 1996 forking lemma):
1. Assume A makes q_H ROM queries + q_S signing queries, forges with prob ε.
2. Reducer B runs A; observes A's ROM queries; programs ROM responses; A produces forge (R*, s*, c*) with c* = H(R*, M*) where M* not signed.
3. Rewind A to point where it queried H(R*, M*); program different c**'; A produces second forge (s**', c**') with same R*.
4. From two equations: s* = r* + c* x, s** = r* + c** x ⇒ x = (s* - s**)/(c* - c**) → B solves DLP.

Concrete bound (non-tight): `Adv^DLP ≥ Adv^Schnorr² / q_H · poly`. Pointcheval-Stern 2000 給 tightness 但仍非 fully tight。

## Results
- **Schnorr signature 被 1990 年代 patent** 直到 2008 expired。Patent 拖延部署。
- **Post-patent 採用**:
  - **Bitcoin BIP-340 (2021) Taproot** — Schnorr 取代 ECDSA, smaller + aggregation。
  - **Ed25519 (Bernstein 2011)** — deterministic Schnorr variant on edwards25519。
  - **EdDSA 標準 RFC 8032**。
  - **MuSig / MuSig2 / FROST** — multi-party Schnorr。

## Limitations / what they don't solve
- **Patent 拖延** 20 年部署；ECDSA 取得標準先機。
- **Pointcheval-Stern reduction 不 tight**：q_H × Adv²；現代多項工作改進但仍非 完全 tight。
- **Original Schnorr 用 random nonce**：與 ECDSA 同樣 nonce-reuse risk；EdDSA deterministic 修補。
- **Pairing-required variants (BLS)** 不同 trust model（更小 sig 但需 pairing-friendly curve）。

## How it informs our protocol design
- **Proteus 用 Ed25519 (deterministic Schnorr)**：直接繼承 Schnorr 結構優勢 + deterministic 避 nonce 災難。
- **Proteus future multi-party mode 可借 MuSig**：若 Proteus 後續支援 multi-server / threshold setup。
- **Proteus transcript hash 結構**：c = H(R ‖ M) — 我們的握手簽章 c = H(transcript) where transcript 含 R + identities + messages。

## Open questions
- **Tight reduction without ROM**: 仍 open。Standard-model Schnorr-like signature 雖有 (Goh-Jarecki 2003) 但效能差。
- **Lattice-based Schnorr-like signature with tight reduction**: ML-DSA / Dilithium 是 lattice-based Fiat-Shamir variant；tightness 仍 active research。

## References worth following
- Schnorr *Identification protocol* (CRYPTO 1989) — Schnorr ID protocol。
- Fiat, Shamir *How to Prove Yourself* (CRYPTO 1986) — Fiat-Shamir heuristic。
- Pointcheval, Stern *Security Arguments for Digital Signatures and Blind Signatures* (Journal of Cryptology 2000) — forking lemma。
- BIP-340 (Bitcoin 2021) Schnorr 部署 spec。
- RFC 8032 — EdDSA (Schnorr variant)。
