# Decaf: Eliminating Cofactors Through Point Compression
**Venue / Year**: CRYPTO 2015
**Authors**: Mike Hamburg
**Read on**: 2026-05-14 (in lesson 3.5)
**Status**: full PDF (`assets/papers/hamburg-ristretto-2015.pdf`)
**One-line**: 在 Edwards curve 上構造 prime-order group abstraction (Decaf448 for curve448, 後 Ristretto255 for curve25519)——消除 cofactor 8 帶來的 protocol-level 陷阱；現代 PAKE / ZK / blind signature 等 advanced protocol 必選。

## Problem
Edwards25519 (Curve25519 Edwards form) group order = 8 × ℓ where ℓ ≈ 2^252 large prime。**Cofactor 8** 在 protocol design 造成多種陷阱：

1. **Identity confusion**: 兩 public keys 可能對應同一 abstract group element（multiply by 8-torsion subgroup element）→ 多個 byte 表示同 logical point。
2. **Small-subgroup attack**: malicious public key in 8-torsion subgroup → DH output 在 small subgroup → 對手 brute force 8 種可能。
3. **Membership testing 易錯**: 接受 invalid encoding (e.g. point not on curve, or in twist) 風險。
4. **Signature malleability**: 在 protocol 中作 commitment 用，cofactor 元素可造 multiple-encoding ambiguity。

X25519 透過 clamping + KDF 解前兩個，但對複雜 protocol（PAKE, threshold sigs, ZK proofs）仍棘手。

## Contribution
1. **Decaf 思想**：把 curve E 商 quotient by 4-torsion subgroup 得 prime-order group D = E/[4]。原 curve 上每 4 points map to 1 D element。透過 encoding scheme 確保 canonical 32-byte representation per D element。
2. **Decaf 用於 Curve448 (Goldilocks)**：原 paper 主要對 Curve448 (cofactor 4) 構造 Decaf448。
3. **Ristretto255 (de Valence-Hamburg 等 2018+)**：把 Decaf 思想 extended to Curve25519 (cofactor 8)。實作為 IETF draft，dalek-cryptography 等 productionize。
4. **Properties achieved**:
   - **Prime-order group** (ℓ ≈ 2^252 elements for Ristretto255)。
   - **Canonical encoding**: every element ↔ unique 32-byte。Decode rejects non-canonical bytes。
   - **No small-subgroup**：encoding 內在 enforce membership in prime-order subgroup。
   - **Same DLP security** as underlying Curve25519。
5. **Composability**：Ristretto 上 protocol 設計可像在 abstract prime-order group 上 work，免處理 cofactor edge cases。

## Method (high-level)
**Decaf encoding (簡化)**：
- Input: point P on Edwards curve。
- Internal: select canonical representative in coset P + 4-torsion。
- Output: 32 bytes representing canonical coordinates。

**Decode**:
- Input: 32 bytes。
- Parse as field element; check `(x, y)` 在 curve 上；確認 canonical (e.g., non-negative x)。
- Reject all non-canonical or 4-torsion variants。

**Group operations**:
- Add, scalar mul 透過 underlying Edwards curve ops + post-process canonicalize。

## Results
- **dalek-cryptography (Rust)** 廣泛採用 Ristretto255。
- **Monero** 用 Ristretto255 做 ring signatures。
- **Signal Protocol** 用於 PAKE-like sub-protocols。
- **IETF CFRG ratified Ristretto255 draft** (draft-irtf-cfrg-ristretto255-decaf448, 2023+) 進入 RFC 流程。
- **MLS (RFC 9420)** 部分 group operation 受益。

## Limitations / what they don't solve
- **不向後相容 X25519**：Ristretto255 不能與 raw Curve25519 byte 互通。X25519 ECDH 仍用 raw curve + clamping + KDF；Ristretto 是另一個 abstraction layer。
- **Curve agnostic 仍 limited**：Decaf/Ristretto 是 Edwards-specific；NIST P-curves 沒有等價 abstraction。
- **Implementation 略複雜**：encode/decode 比 raw curve ops 多 ~30% cost。

## How it informs our protocol design
- **G6 key exchange 用 X25519 raw**：因為 WireGuard 互通 + RFC 7748 標準 + 簡單。
- **G6 advanced protocol（PAKE, blinded auth, ZK proof）用 Ristretto255**：避免 cofactor 陷阱。
- **G6 cover-traffic 設計**：若用 Elligator2 把 pk 偽裝為 random bytes，必須在 Ristretto255 上做（X25519 的 cofactor 會洩部分 information through twist-side 偵測）。

## Open questions
- Decaf/Ristretto 在 post-quantum group action (CSIDH) 是否有對應 abstraction？open。
- Constant-time decode 在 hardware-level timing leakage 下的 robustness 仍 active。

## References worth following
- Hamburg *Ed448-Goldilocks, a new elliptic curve* (2015) — Curve448 + Decaf448。
- de Valence 等 *Ristretto255 IETF draft*。
- libsodium docs on Ristretto255 usage。
- dalek-cryptography crate (`curve25519-dalek::ristretto`)。
