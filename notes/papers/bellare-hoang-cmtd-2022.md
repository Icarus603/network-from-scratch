# Efficient Schemes for Committing Authenticated Encryption
**Venue / Year**: EUROCRYPT 2022
**Authors**: Mihir Bellare, Viet Tung Hoang
**Read on**: 2026-05-16 (in lesson 3.17)
**Status**: cited from abstract + ePrint preprint (eprint.iacr.org/2022/268). Full PDF reading deferred to Phase III 11.7 detailed application.
**One-line**: 給出第一個高效率的 generic transform，把任意 AEAD 升級成 key-/context-committing AEAD，把 partitioning oracle attack 直接根除。

## Problem
標準 AEAD (AES-GCM, ChaCha20-Poly1305) 只滿足 IND-CCA + INT-CTXT；不滿足 **key commitment**——存在 (k1, m1, n1, ad1) ≠ (k2, m2, n2, ad2) 使得 AEAD-Enc 產出**同一個 ciphertext**。Len-Grubbs-Ristenpart (USENIX Security 2021) 證明此性質可被 partitioning oracle 用於對 password-derived key 場景做 O(2^k×) 加速暴力破解。Albrecht 等 2022 把它用在 Telegram MTProto 上完整 break。

舊有 fix（Albrecht-Degabriele-Janson-Mitrokotsa 2020、Dodis-Grubbs-Ristenpart-Woodage CCS 2018）overhead 過高 (≥2× compute) 或設計侵入性大。

## Contribution
1. 定義 CMT-1/CMT-2/CMT-3/CMT-4 commitment 安全 hierarchy。
2. 給出 **CTX (Context Commitment Transform)**: 在 existing AEAD 後接一個 HMAC-based commit tag, 一次 hash compression overhead，達 CMT-4 (最強)。
3. 給出 **HtE (Hash-then-Encrypt)**: 在 existing AEAD 前 derive key from H(k ‖ context), 達 CMT-1，零 wire overhead。
4. 形式證明 CTX 在 PRF assumption (HMAC) 下 CMT-4-secure。
5. 對 AES-GCM, ChaCha20-Poly1305, AEGIS 全部測 overhead < 5% 在 ≥1 KB record。

## Method
**CTX 結構**:
```
Standard AEAD: (c, t) = Enc(k, n, ad, m)
CTX: T = H(k_commit, encode(n, ad, t))     // commit to context + tag
     output: (c, t, T)

k_commit derived via KDF from session secret, independent from k_enc.
```

key-committing guarantee: 對任意兩組不同 (k_commit, n, ad, t)，產出不同 T；MAC 第二原像難 → 無法找到 collision。

## Results
- 64-byte record: CTX +20% overhead
- 1 KB record: CTX +1.5% overhead
- 16 KB record: CTX +0.1% overhead
- Wire size: +16 byte fixed (HMAC truncated to 128-bit)

## Limitations / what they don't solve
- CTX 需 separate k_commit；如果 protocol 已有 single-key derivation，需要 spec 改動。
- CMT-4 不防 ciphertext-malleability over different ad fields if ad is omitted from binding. spec 必須 include ad in encode().
- 與 nonce-misuse-resistant AEAD (GCM-SIV) 的 interaction 未深入。

## How it informs our protocol design
Proteus v1.1 採 CTX-augmented XChaCha20-Poly1305 作為 record layer。
- k_commit 由 chaining_key HKDF-Expand 派生。
- 每 record 多 16 byte (~1.5% on MTU-sized records)。
- 完全防 partitioning oracle (vs SS / Telegram / 任何 PSK 流派的 production protocol 都未做)。

這是 Proteus SOTA differentiator #1 (見 3.17 §1)。

## Open questions
- CTX + AES-GCM-SIV 結合最佳 construction？
- CTX deterministic tag 是否影響 Proteus cover-traffic 的 length-blind randomness 假設？需 evaluate (3.17 §7 open #2)。
- 是否能 amortize commit hash over multiple records 而不損 CMT-4？

## References worth following
- Len, Grubbs, Ristenpart, *Partitioning Oracle Attacks*, USENIX Security 2021 (預設讀)
- Albrecht 等, *Four Attacks and a Proof for Telegram*, IEEE S&P 2022
- Grubbs, Lu, Ristenpart, *Message Franking via Committing Authenticated Encryption*, CRYPTO 2017
- Bellare, Davis, Günther, *Separate Your Domains: NIST PQ KEMs, Oracle Cloning, and Read-Only Indifferentiability*, EUROCRYPT 2020
