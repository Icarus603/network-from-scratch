# Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange
**Venue / Year**: PQCrypto 2019
**Authors**: Nina Bindel, Jacqueline Brendel, Marc Fischlin, Brian Goncalves, Douglas Stebila
**Read on**: 2026-05-16 (in lesson 3.17)
**Status**: cited from abstract + ePrint (eprint.iacr.org/2018/903). Full deep read deferred to Phase III 11.11 hybrid combiner proof.
**One-line**: 給出第一個完整的 hybrid KEM 安全模型與形式化證明：如果其中**任一** component KEM 是 IND-CCA2，則正確 combine 後的 hybrid KEM 也是 IND-CCA2。

## Problem
PQ 過渡期，業界共識是用 classical + PQ KEM hybrid（X25519 + ML-KEM-768 等）。但**怎麼 combine** 兩個 shared secret 缺乏統一 formal treatment：
- XOR: 不安全（adversary 控制一個 share 可影響 output）
- Concatenation only: KDF assumption 下不夠
- 含 ciphertext: 直觀但需 proof

之前 Giacon-Heuer-Poettering PKC 2018 給 KEM combiner 構造，但安全 game 對 hybrid AKE 不完整。

## Contribution
1. 定義 **KEM combiner** 安全 game (dual-PRF based)。
2. 給出 4 個 combiner construction，比較哪個給「OR-secure」(只要一個 component 安全則 hybrid 安全)。
3. 證明 **"含 ciphertext + KDF" combiner** (Construction "XtKEM") 在 standard model 下 dual-PRF assumption 給 IND-CCA2 OR-secure。
4. 將 KEM combiner 延伸到 hybrid AKE (KEMTLS-like protocols)。
5. 給出 ProVerif/Tamarin-friendly abstraction，便於後續 protocol-level proof。

## Method
**Secure combiner construction**:
```
C(KEM_A, KEM_B).Encap(pk_A, pk_B):
    (c_A, K_A) ← KEM_A.Encap(pk_A)
    (c_B, K_B) ← KEM_B.Encap(pk_B)
    K = KDF(K_A ‖ K_B ‖ c_A ‖ c_B)    // ciphertext binding crucial
    return ((c_A, c_B), K)
```

**Theorem 3.4**: under dual-PRF assumption on KDF and IND-CCA2 of either KEM_A or KEM_B:
```
Adv^IND-CCA2_C(A) ≤ Adv^IND-CCA2_KEM_A(A') + Adv^dual-PRF(A'')
                  OR
                ≤ Adv^IND-CCA2_KEM_B(A') + Adv^dual-PRF(A'')
```

Proof goes by game hops:
1. Replace K_A with random (under KEM_A IND-CCA2 if relying on A).
2. dual-PRF (with K_A random or K_B random as secret) → KDF output indistinguishable from random.

**Without ciphertext binding**: combiner not OR-secure; needs both KEMs simultaneously IND-CCA。

## Results
形式化結果，無實驗數據。但 spec 推薦：
- combiner: KDF(K_A ‖ K_B ‖ c_A ‖ c_B)
- KDF: HKDF-Extract with transcript hash as salt
- Sufficient for TLS 1.3 hybrid spec, IETF CFRG hybrid drafts

## Limitations / what they don't solve
- Dual-PRF assumption 雖標準 (HKDF 滿足) 但非最弱 KDF assumption。
- No treatment of authenticated KEMs。
- 沒考慮 hybrid PCS (ratchet 場景)，後續 Brendel-Fischlin-Günther 2022 補。
- KEM combiner 沒處理 KEM 之間 key length 差異引發的 length-leak side channel。

## How it informs our protocol design
G6 hybrid combine spec (見 3.17 §3 & 3.11 §9):
```
K_hybrid = HKDF-Extract(
    salt = transcript_hash,
    ikm  = K_X25519 ‖ K_MLKEM ‖ ct_X25519 ‖ ct_MLKEM
)
```

完全按 Bindel et al. Construction "XtKEM"。

**Justification**: G6 session key IND-CCA2 secure if either X25519 ECDH or ML-KEM-768 IND-CCA2 holds。對 PQ 過渡期最 robust 的 choice。

**Verification (Phase III 11.11)**: CryptoVerif game-based proof reproducing Bindel et al. Thm 3.4 with G6-specific KDF instantiation。

這是 G6 SOTA differentiator #3 (見 3.17 §3)。

## Open questions
- Hybrid PCS (ratchet under hybrid KE) — Brendel-Fischlin-Günther 2022 已開始，但未完整 (G6 可貢獻)。
- Hybrid + 0-RTT: 0-RTT 場景下 combiner 安全性無 formal treatment。
- Hybrid + KEMTLS: Schwabe-Stebila-Wiggers 2020 framework 與本論文整合的具體 spec。
- Multi-KEM (3+ components) combine 是否帶來新 attack vector？

## References worth following
- Giacon, Heuer, Poettering, *KEM Combiners*, PKC 2018
- Brendel, Fischlin, Günther, *Hybrid Key Exchange with Forward Secrecy and Post-Compromise Security*, 2022
- IETF CFRG draft-ietf-tls-hybrid-design
- Stebila-Mosca, *Post-Quantum Key Exchange for the Internet and the Open Quantum Safe Project*, SAC 2016
- Cremers, Düzlü, Friedl, Sasaki, Spies, *BUFFing Signature Schemes Beyond Unforgeability*, IEEE S&P 2021 (signature-side hybrid analog)
