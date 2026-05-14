# The Order of Encryption and Authentication for Protecting Communications (or: How Secure Is SSL?)
**Venue / Year**: CRYPTO 2001（LNCS 2139, pp. 310–331）。Full version: IACR ePrint 2001/045
**Authors**: Hugo Krawczyk（IBM Research）
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: ePrint + Springer 開放
**One-line**: 「先加密後 MAC」（encrypt-then-MAC, EtM）是唯一在 generic composition 下永遠安全的；SSL/TLS 1.0–1.2 採用的 MAC-then-encrypt 17 年後才被業界拋棄。

## Problem
- 設計 secure channel 時，要組合 symmetric encryption + MAC。三種順序：
  1. **Encrypt-then-MAC (EtM)**：ciphertext = Enc(k1, M)；tag = MAC(k2, ciphertext)；傳 (ciphertext, tag)
  2. **MAC-then-encrypt (MtE)**：tag = MAC(k2, M)；ciphertext = Enc(k1, M || tag)；傳 ciphertext。SSL/TLS、IPsec ESP 部分 mode 用此
  3. **Encrypt-and-MAC (E&M)**：ciphertext = Enc(k1, M)；tag = MAC(k2, M)；傳 (ciphertext, tag)。SSH 用此
- 業界長期沒有理論上「哪一種安全」的共識，憑直覺挑

## Contribution
1. **形式化證明：EtM 在 generic composition 下安全**（IND-CCA + UF-CMA → secure channel）
2. **反例：MtE 不是 generically secure**——存在 IND-CPA secure encryption + UF-CMA secure MAC 組合後變 totally insecure 的 construction（具體例子：Shannon-perfect-secrecy 的 OTP + 任意 MAC，組合後可被 active attacker 解出密文）
3. **MtE 在「特殊」加密 mode 下安全**：CBC + secure block cipher，或 stream cipher（xor with PRG）。SSL/TLS 因此「實際上」沒爆——但是巧合，不是設計。
4. **E&M（SSH）一般也不安全**

## Method (just enough to reproduce mentally)
- Game-based proof：定義 secure channel 為「authenticated encryption with associated data」雛形
- 對 EtM：歸約到底層 Enc 的 IND-CPA + MAC 的 UF-CMA
- 對 MtE：構造 counter-example——OTP encrypt(M || tag) 之後，attacker 可以 flip ciphertext bit 直接 flip plaintext bit，因為 MAC 無法檢測（MAC 被加密了，attacker 沒看到，但 plaintext 本身被解出時 tag 也被 flip）→ 但 MAC 被加密的 tag 也 flip 對應 plaintext bit 不可預測，舉的反例顯示某些 encryption 構造下可被 distinguish
- 對 E&M：MAC 直接洩漏 M 的等價類，違反 IND-CPA

## Results
- 業界正確答案：**永遠 encrypt-then-MAC**
- 但 TLS 1.0/1.1/1.2 在發 RFC 時已選 MtE，且 CBC mode 巧合救了它（直到 Lucky13 用 timing side channel 把這個巧合也打破）
- IPsec 早於 RFC 4309 已選 EtM
- SSH 用 E&M，但 RFC 4344 後加 ChaCha20-Poly1305 AEAD 變相 EtM

## Limitations / what they don't solve
- 不討論 AEAD 統一原語的安全（後續 Rogaway 等人補上）
- 不討論 nonce 處理、padding length 隱藏

## How it informs our protocol design
- **永遠 AEAD**（這是「fused EtM」）
- **永遠不發明新 MAC composition**
- 我們協議的 record layer 直接套用 AES-GCM / ChaCha20-Poly1305 / AES-GCM-SIV（後者解 nonce reuse 問題）

## Open questions
- 在 misuse-resistant 場景（nonce reuse）下，EtM 的 generic 結論需修正：要 AEAD-SIV
- Post-quantum 場景下對稱原語仍 EtM 可用，但 MAC 強度要重新評估

## References worth following
- Bellare & Namprempre. *Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm*. ASIACRYPT 2000
- Rogaway. *Authenticated-Encryption with Associated-Data*. CCS 2002
- Canetti & Krawczyk. *Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels*. EUROCRYPT 2001

---

**用於課程**：Part 4.1（為何 1.3 拿掉 MtE）、Part 3.8（AEAD theory）、Part 4.3（record layer 細節）
