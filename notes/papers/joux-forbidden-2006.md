# Authentication Failures in NIST version of GCM (the "Forbidden Attack")
**Venue / Year**: NIST 800-38D Draft Comments, 2006
**Authors**: Antoine Joux
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: full PDF (`assets/papers/joux-forbidden-2006.pdf`)
**One-line**: 證明 GCM 在同一 (key, IV) 對下加密兩個訊息會洩露 GHASH subkey H = AES_K(0)，繼而打破整個 INT-CTXT——這就是「nonce-misuse 對 GCM = 死刑」的 formal evidence；TLS 1.3 / RFC 8446 的 nonce 構造規則直接源自此論文。

## Problem
2004-2005 年 NIST 在 800-38D 草案標準化 GCM。Joux 指出：草案中的 IV 構造允許 64-bit IV（除了標準的 96-bit），這在 birthday bound 下 q ≈ 2^32 後極可能 collision；一旦 IV collision，GCM 的 authentication 完全崩潰。論文同時警告**任何 scenario** 下 nonce 重用會產生 catastrophic failure，不只是 confidentiality 而是 authenticity。

## Contribution
**Forbidden Attack 完整推導**：

設 same key K、same IV → 兩 ciphertext (C_1, T_1) 與 (C_2, T_2) for plaintexts P_1, P_2。
- C_1 XOR C_2 = P_1 XOR P_2（CTR keystream cancel）。**Confidentiality 立刻崩**。

**更糟的是 authenticity**：
- Tag T_i = GHASH_H(A_i, C_i) XOR EK_J0，其中 EK_J0 = AES_K(J_0) 是 same（same IV ⇒ same J_0）。
- T_1 XOR T_2 = GHASH_H(A_1, C_1) XOR GHASH_H(A_2, C_2)。
- 將 GHASH 視為 H 的多項式：
  ```
  GHASH_H(A, C) = Σ_i x_i · H^{q-i}    (in GF(2^128))
  ```
- 兩組已知 (A_1, C_1, T_1) 與 (A_2, C_2, T_2) → 多項式方程 in unknown H of degree ≤ q。
- 解這個方程 → **recover H**。
- 拿到 H，對手能對任意新 (A', C') 計算正確 tag T' = GHASH_H(A', C') XOR EK_J0。**INT-CTXT 完全打破**。

額外貢獻：
- 警告草案的 64-bit IV 提案（容易 birthday）。
- 推動 NIST 把 IV 主推 96-bit + 強烈建議 random IV（隨機性給 birthday 緩衝）。
- 引發後續 misuse-resistant AEAD 設計潮（GCM-SIV、AEZ、Deoxys-II）。

## Method
**Polynomial reconstruction over GF(2^128)**：

```text
GHASH_H(A, C) for AAD A and ciphertext C parsed as blocks:
    let blocks = A_1 ‖ ... ‖ A_a ‖ C_1 ‖ ... ‖ C_c ‖ (len(A) ‖ len(C))
    GHASH_H(A, C) = Σ_{i=1}^{a+c+1} blocks_i · H^{a+c+2-i}    (XOR sum in GF(2^128))

對手得 (T_1 XOR T_2) = Σ (blocks_1,i XOR blocks_2,i) · H^{...}
                    = Polynomial in H of known coefficients

In GF(2^128), polynomial of degree d has ≤ d roots。
Use BERLEKAMP / Cantor-Zassenhaus 或 Brent-Kung GCD 找根。
通常只有少數候選 H；對每個 candidate 用第三個 forge 檢驗即可確認。
```

執行成本：對 q ≈ 1000 block 的訊息，root-finding 在現代 CPU 上 ms 級完成。

## Results
- **NIST 800-38D 最終標準** (2007) 強烈建議 96-bit IV + 隨機構造 + 同 key 下 ≤ 2^32 invocation。
- **TLS 1.2 GCM (RFC 5288)** 規範 explicit 64-bit nonce + per-record sequence；implicit + explicit 確保 uniqueness。
- **TLS 1.3 (RFC 8446)** Section 5.3 規範：Per-record nonce = sequence_number XOR per-direction static_iv（96-bit）。
- **2016 Böck-Zauner-Devlin 等** 發現 7 個真實 HTTPS site 用 random IV with poor RNG 重用 → forbidden attack 在野實證。
- **WireGuard** 為避此風險改用 ChaCha20-Poly1305（雖然 ChaCha20-Poly1305 也怕 nonce reuse，但 nonce 來源 deterministic counter 不靠 randomness）。

## Limitations / what they don't solve
- 不解決 GCM 設計本身——只警告。後續 GCM-SIV (Gueron-Lindell 2015) 才從根本提供 misuse-resistance。
- 不涵蓋 partial nonce reuse（同 prefix 不同 suffix）的 attack；後 Bock 等 2016 補。
- 不涵蓋 multi-key 場景；Bellare-Tackmann 2016 補。

## How it informs our protocol design
- **Proteus nonce 必 deterministic counter**，不靠 randomness：避免 RNG 失誤。
- **Proteus nonce 結構含 epoch + direction + counter**：counter 重置 (overflow) 觸發 ratchet 升 epoch，避免 nonce reuse。
- **Proteus 0-RTT 用 GCM-SIV (RFC 8452)**：0-RTT 場景下 nonce 可能 implicitly reuse（client 沒收到 server reply 重 retry），SIV 結構保證 nonce 重用只洩 message equality，不洩 key。
- **Proteus spec 寫明 nonce-misuse 後果**：明確標示「任何 implementation 重用 (key, nonce) → 整個 session security 崩潰」。

## Open questions
- 對手只有 partial nonce reuse 時的 forge probability tight bound？仍 active。
- Misuse-resistant AEAD 在 quantum oracle 下的 security 仍 open。

## References worth following
- McGrew, Viega *The Galois/Counter Mode of Operation (GCM)* (NIST 2004) — GCM 原始 spec。
- Gueron, Lindell *GCM-SIV: Full Nonce Misuse-Resistant Authenticated Encryption at Under One Cycle per Byte* (CCS 2015) — misuse-resistant 解法。
- Bock, Zauner, Devlin, Somorovsky, Jovanovic *Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS* (USENIX WOOT 2016) — 在野實證。
- RFC 8452 — AES-GCM-SIV standardization。
