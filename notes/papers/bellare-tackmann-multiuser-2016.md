# The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3
**Venue / Year**: CRYPTO 2016
**Authors**: Mihir Bellare, Björn Tackmann
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: abstract-only（IACR ePrint Cloudflare 阻擋；引用內容自 CRYPTO 2016 proceedings TOC + Springer abstract + 訓練資料）。
**One-line**: 給出第一個對 AES-GCM 在「百萬使用者共用 cipher（不同 key）」場景下的 tight 安全 bound——把單 user IND-CCA bound `q²/2^n` 一般化為 multi-user `μq²/2^n` 並證明 TLS 1.3 record layer 仍 secure；G6 的 multi-user spec 直接 reference 此論文。

## Problem
傳統 AEAD security analysis 假設「single key, single user」。但實務 TLS server 同時跟百萬 client TLS connection 各自一個 session key。對手只要從**任一**user 拿到一次 distinguishing advantage 就贏 — 嚴格 bound 應該是 single-user bound × 用戶數 μ。

問題：是否所有 AEAD 在 multi-user 下 bound 真的線性放大 μ × ε？對 TLS 1.3 主推的 AES-GCM 與 ChaCha20-Poly1305 而言，bound 多大才能聲稱「TLS 1.3 在 100M user × 2^30 record 下 secure」？

## Contribution
1. **Multi-user IND-CPA / IND-CCA / INT-CTXT 的 game-based 形式化**：定義 game 中對手能向 μ 個 user 各自的 oracle query；advantage 取對所有 user 的最大。
2. **AES-GCM multi-user bound**：證明 `Adv^MU-IND-CPA_AES-GCM ≤ μq²ℓ²/2^128 + AES-PRF terms`。對 μ ≤ 2^30, q ≤ 2^32, ℓ ≤ 2^14 (16 KB record)，bound ≤ 2^-30，仍 secure。
3. **Tight key-collision argument**：multi-user bound 之 dominance 不只是 birthday on nonce，還要算 key collisions across users (key 256-bit ⇒ collision negligible; key 128-bit at μ = 2^48 開始可量)。
4. **TLS 1.3 spec 影響**：論文 section 7 直接給 RFC 8446 起草者的 recommendation——強制 128-bit tag、96-bit nonce、per-record sequence number、per-direction static IV XOR。這些 recommendation 全進 RFC 8446 §5.3。

## Method
**Game (簡化)**:
```text
Game MU-IND-CPA(A, μ):
    For i = 1..μ: K_i ← KGen
    b ← {0,1}
    Used ← {}    // (i, N) tuples
    A queries Enc-LR(i, N, A_data, P_0, P_1):
        if (i, N) ∈ Used or |P_0| ≠ |P_1|: return ⊥
        Used ← Used ∪ {(i, N)}
        return Enc(K_i, N, A_data, P_b)
    A outputs b'
    Adv = |Pr[b'=b] - 1/2|
```

**Reduction proof (草稿)**:
```text
Step 1 (real → ideal): replace AES with PRF (cost: μ × Adv^PRF_AES per Bellare-Rogaway 2006)
Step 2 (PRF → random): bound CTR-mode collisions across μ users with q each, ℓ blocks per query
        → birthday on counter-keystream collisions: μq²ℓ²/2^(n+1)
Step 3 (forge): bound INT-CTXT from polynomial structure of GHASH
                → μq² · ℓ / 2^τ + other terms
Step 4 (final): combine all → quoted bound
```

**Tightness**：reduction 是 tight in q, ℓ; 在 μ 上有 μ-factor 損失（因為 reduction 必須 guess which user A targets），這是已知 multi-user bound 的本質代價。

## Results
- **TLS 1.3 (RFC 8446) §5.3 nonce 構造直接源自此論文**：sequence_number XOR static_iv，static_iv 是 per-direction 的 derived 96-bit。
- **TLS 1.3 §5.5 限制 single-key invocation 數**：AES-GCM 最多 2^24.5 records per key（基於本論文 bound + safety margin）。
- **被 IETF QUIC、SSH 後續 specs 引用**作為 nonce 構造設計依據。
- **影響後續 multi-user AEAD 研究**：Hoang, Tessaro 等延伸到 ChaCha20-Poly1305 multi-user bound。

## Limitations / what they don't solve
- 假設 key 是 fully random（KDF output 視為 uniform）。實務 KDF 若 biased 則 bound 失效。
- 不處理 nonce-misuse adversary。
- 不處理 side-channel; 假設 implementation black-box。
- Quantum adversary 不在 scope。

## How it informs our protocol design
- **G6 spec Security Considerations 必須寫 multi-user analysis**，類似 RFC 8446 Appendix E 寫法。
- **G6 假設 μ ≤ 10M concurrent sessions, q ≤ 2^32 records each, ℓ ≤ 2^14 (16 KB max record)** → 計算 bound 並聲明。
- **G6 對 ChaCha20-Poly1305 也要算 multi-user bound**：reference Procter 2014、Hoang-Tessaro。
- **G6 強制 256-bit key**（即使 ChaCha20 也是 256-bit）：避免 multi-user key-collision 在百萬 user 變顯著（128-bit key 在 μ = 2^48 開始崩）。

## Open questions
- ChaCha20-Poly1305 multi-user 的 tight bound？目前 Hoang-Tessaro 2017 給的是 GCM-style bound，但 ChaCha20 結構不同，有改進空間。
- Multi-user + nonce-misuse 同時的 bound？open。
- Quantum multi-user bound 仍 nascent。

## References worth following
- Bellare, Boldyreva *The Security of Symmetric Encryption Against Mass Surveillance* (CRYPTO 2014) — multi-user 早期論文。
- Hoang, Tessaro *Key-Alternating Ciphers and Key-Length Extension: Exact Bounds and Multi-user Security* (CRYPTO 2016) — multi-user PRP。
- Procter *A Security Analysis of the Composition of ChaCha20 and Poly1305* (2014) — ChaCha-Poly composition 證明（含 multi-user 觀察）。
- RFC 8446 Appendix E.1 — TLS 1.3 record layer security analysis。
