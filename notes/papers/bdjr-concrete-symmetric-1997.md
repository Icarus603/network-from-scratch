# A Concrete Security Treatment of Symmetric Encryption
**Venue / Year**: IEEE Symposium on Foundations of Computer Science (FOCS) 1997
**Authors**: Mihir Bellare, Anand Desai, Eron Jokipii, Phillip Rogaway
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: full PDF (`assets/papers/bdjr-concrete-1997.pdf`)
**One-line**: 把對稱加密的 IND-CPA / IND-CCA 從 1980 年代的 asymptotic 寫法升級到 concrete security——給出明確的 q × ε bound，讓現代 spec（RFC、NIST FIPS）能直接寫進「在 q = 2^48 query 下優勢 ≤ 2^-32」這種可驗證敘述。

## Problem
Goldwasser-Micali (1984) 開創了 semantic security 的 game-based 定義，但 1980-1990 年代主流寫法都是 asymptotic：「對所有 PPT adversary，advantage 是 negligible」。這在工程上有兩個無解的問題：
1. **無法給出具體金鑰大小建議**。Asymptotic 說 n → ∞，但實務 AES 是 fixed 128-bit。
2. **無法給出具體使用上限**。例如 GCM 用同一個 key 做 q 次加密、每次至多 ℓ blocks，q 跟 ℓ 多大時安全會崩？

## Contribution
1. **將 IND-CPA / IND-CCA 改寫為 concrete security**：不再說 "negligible"，而說「對所有資源 (t, q_e, q_d, μ) bounded 的 adversary，advantage 是 explicit function of these resources」。
2. **正式定義各種對稱加密 mode**：CTR、CBC、CTR$、各自的 security bound。為 NIST SP 800-38 系列文件提供理論基礎。
3. **PRF / PRP 區分對 mode 的 implication**：
   - CTR mode 只需 PRF 假設（hence ChaCha20 適用）。
   - CBC mode 需要 PRP 假設（hence 必須是 block cipher）。
4. **Birthday bound 的精確化**：CBC、CTR 的 IND-CPA bound 都有 `q² · ℓ² / 2^n` 項，n = block size。AES (n=128) 在 q · ℓ ≈ 2^32 blocks (≈ 64 GB) 後 advantage 開始可量；ChaCha20 (n=512 effective state) 不受此 bound 困擾。

## Method (just enough to reproduce mentally)
**核心技術：reduction proof + game hopping**。要證 CTR mode IND-CPA：

```text
Game G_0: real IND-CPA with CTR_F where F is PRF
Game G_1: replace F with truly random function R
Game G_2: trivial (random ctxt vs random ctxt is uniform)

| Pr[A wins G_0] - Pr[A wins G_1] | ≤ Adv^PRF_F(B)  // by PRF assumption
| Pr[A wins G_1] - Pr[A wins G_2] | ≤ q² · ℓ² / 2^(n+1)  // birthday on counter collision
| Pr[A wins G_2] - 1/2 | = 0

⇒ Adv^IND-CPA_CTR_F(A) ≤ Adv^PRF_F(B) + q² · ℓ² / 2^(n+1)
```

這個寫法現在是**現代密碼學論文的範式**——TLS 1.3 安全性證明 (Dowling-Fischlin-Günther-Stebila 2015) 就是這樣寫。

## Results
- 將 GCM、CCM、CBC、CTR 的 security bound 全部寫清楚。
- 為 RFC 5116 (AEAD interface) 提供「最大允許 invocation 數」的計算依據。
- TLS 1.3 RFC 8446 Appendix E 的 security considerations 直接繼承這套 concrete security 寫法。

## Limitations / what they don't solve
- 只處理 chosen-plaintext / chosen-ciphertext，不處理 misuse-resistance。後者由 Rogaway-Shrimpton 2006 *SIV* 補上。
- 不處理 multi-key / multi-user setting。Bellare-Tackmann 2016 補上。
- 不考慮 nonce-misuse。實務 GCM 一旦 nonce 重用就 catastrophic（Joux 2006 forbidden attack）；現代設計改用 misuse-resistant AEAD（XChaCha20-Poly1305、AES-GCM-SIV）。

## How it informs our protocol design
- **G6 必須在 spec 給 concrete bound**：例如「同一 session 至多 2^48 個 record，每 record 至多 16 KB；Adv ≤ 2^-32」。
- **G6 必須計算 nonce space**：12-byte AEAD nonce ⇒ 2^96 unique。我們用 8-byte epoch + 4-byte counter，counter 達上限觸發 rekey。
- **G6 必須 multi-user-aware**：spec 內必須 reference Bellare-Tackmann 2016 給的 multi-user bound。

## Open questions
- ChaCha20 的 multi-key tight bound 在 nonce-misuse 下尚未完全解決（Bellare-Bernstein-Tessaro 2016 是當前最強）。
- 對 G6 的 cover traffic 場景，concrete security 模型需要擴充以涵蓋「假流量被解密失敗」對 advantage 的影響——open problem。

## References worth following
- Bellare, Rogaway, *The Security of Triple Encryption and a Framework for Code-Based Game-Playing Proofs* (EUROCRYPT 2006) — game hopping 的 modern 範本。
- Shoup, *Sequences of Games* (IACR 2004/332) — 同主題的 tutorial。
- Bellare, Tackmann, *The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3* (CRYPTO 2016) — multi-user bound。
- Rogaway, *Nonce-Based Symmetric Encryption* (FSE 2004) — nonce-based AEAD 的 framework。
