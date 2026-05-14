# Short Signatures from the Weil Pairing
**Venue / Year**: ASIACRYPT 2001（Journal of Cryptology 2004 expanded）
**Authors**: Dan Boneh, Ben Lynn, Hovav Shacham
**Read on**: 2026-05-14 (in lesson 3.7)
**Status**: abstract-only（IACR archive Cloudflare 阻擋；引用內容綜合自 ASIACRYPT 2001 proceedings + Stanford Boneh page + 訓練資料）
**One-line**: 第一個 pairing-based short signature——用 elliptic curve bilinear pairing 達到 signature size 約 elliptic curve point size (vs Schnorr/EdDSA 的 2x)；同 message 不同 signer 的 signatures 天然 aggregate；Ethereum 2.0 用 BLS12-381 部署 32k validator aggregation。

## Problem
2001 年最短 signature: DSA / Schnorr ~2|q| bits (e.g., 512-bit for 128-bit security)。RSA-2048 signature 是 2048-bit。能否更短？

Bilinear pairing 在 ECC 早期 (Joux 2000 三方一輪 KEX) 顯示可創造新 primitive。Boneh-Lynn-Shacham 想：能不能用 pairing 構造 short signature？

## Contribution
1. **BLS signature**:
   ```text
   Setup: pairing-friendly curves G_1, G_2 with bilinear map e: G_1 × G_2 → G_T
          base points P_1 ∈ G_1, P_2 ∈ G_2
          Hash function HashToCurve: M → G_1
   
   KGen:
       sk = x ← random in Z_q
       pk = x · P_2 ∈ G_2
   
   Sign(sk, M):
       H = HashToCurve(M) ∈ G_1
       σ = x · H ∈ G_1
       return σ
   
   Verify(pk, M, σ):
       H = HashToCurve(M)
       return e(σ, P_2) == e(H, pk)
   ```
2. **Signature size**: 1 element of G_1 (e.g., 48 byte on BLS12-381) vs Schnorr 64 byte。
3. **Aggregation**: 同 message 不同 signer 的 σ 直接 σ_agg = Σ σ_i (group addition)；verify: e(σ_agg, P_2) == e(H, Σ pk_i)。
4. **Unique signature**: deterministic given (sk, M)；canonical encoding；sUF-CMA。

## Method (high-level)
**Bilinear pairing**: e: G_1 × G_2 → G_T 滿足：
- Bilinear: e(aP, bQ) = e(P, Q)^(ab)。
- Non-degenerate: e(P_1, P_2) ≠ 1。
- Efficiently computable。

**Verification 正確性**:
```text
e(σ, P_2) = e(x · H, P_2)
          = e(H, P_2)^x       (bilinear)
          = e(H, x · P_2)     (bilinear in other slot)
          = e(H, pk)          ✓
```

**Aggregation**:
```text
σ_agg = σ_1 + σ_2 + ... + σ_n
      = x_1 H + x_2 H + ... + x_n H
      = (x_1 + ... + x_n) · H

pk_agg = pk_1 + ... + pk_n = (x_1 + ... + x_n) · P_2

verify: e(σ_agg, P_2) == e(H, pk_agg)    ✓
```

對**不同 messages** 的 aggregation 需 ∏ e(H_i, pk_i) check。

## Results
- **BLS 在 region of 2000-2010 被 patent 部分限制**，2010 後 expire。
- **Ethereum 2.0 (Beacon Chain, 2020+)** 用 BLS12-381 做 validator signature aggregation：32k validators per slot → 1 σ.
- **Filecoin、Chia、Diem (defunct)** 用 BLS。
- **Threshold BLS** (Boldyreva 2003) 廣泛用於 DKG / threshold cryptocurrency wallet。
- **Drand (League of Entropy)** 用 threshold BLS 給 distributed randomness beacon。

## Limitations / what they don't solve
- **Pairing 計算昂貴**: 比 elliptic curve scalar mul 慢 ~10-50×。Sign 快但 verify 慢。
- **Rogue-key attack**: 對手選 pk' s.t. pk_agg = aggregated includes 對手 forge。修補: proof-of-possession 或 hash-based key tweaking (Bellare-Neven 2006)。
- **Curve selection critical**: pairing-friendly curves (BN, BLS) 有 specific structure；BLS12-381 是當前 standard with 128-bit security。
- **No deterministic nonce option**：但 deterministic by construction (no nonce needed)。
- **Quantum-vulnerable**：Shor 對 ECDLP 可破，pairing-based 同樣脆弱。

## How it informs our protocol design
- **G6 不直接用 BLS**：理由——
  - Pairing computation overhead 對單 client-server proxy 不需要。
  - G6 不是 BFT consensus，沒 aggregation 需求。
- **G6 借鑑 BLS aggregation 概念**：未來若 G6 加 group mode (multi-server failover, threshold backup key)，BLS 是候選。
- **G6 對 BLS-based PKI 兼容**：若未來 cert chain 用 BLS，G6 需 BLS verify support。

## Open questions
- **Post-quantum BLS-equivalent**: 仍 open. Lattice-based aggregatable signature 是 active research。
- **Concurrent rogue-key-resistant aggregation**: MuSig2 framework 不直接適用 BLS。
- **Pairing computational improvements**: 持續 paper 在 reduce pairing cost。

## References worth following
- Boneh-Boyen *Short Signatures Without Random Oracles* (EUROCRYPT 2004) — standard-model variant。
- Boldyreva *Efficient Threshold Signature, Multisignature and Blind Signature Schemes Based on the Gap-Diffie-Hellman-Group Signature Scheme* (PKC 2003) — threshold BLS。
- Boneh-Drijvers-Neven *Compact Multi-Signatures* (ASIACRYPT 2018)。
- Bellare-Neven *Multi-signatures in the plain public-key model* (CCS 2006) — rogue-key analysis。
