# SIGMA: The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE Protocols
**Venue / Year**: CRYPTO 2003
**Authors**: Hugo Krawczyk
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: abstract-only（IACR archive PDF behind Cloudflare 403; HuJI mirror down; 引用內容綜合自訓練資料 + Springer abstract + author homepage 摘要）。我嘗試了 IACR archive、Semantic Scholar PDF、author webee.technion.ac.il 三個來源，前兩者 403/empty，第三者 HTML 錯誤。
**One-line**: 把「DH 認證」這個 1990 年代纏訟未決的問題用 SIGn-and-MAc 結構徹底解決——指出簽章必須**只簽 ephemeral DH share**而不是整個 transcript，再用 MAC 綁 identity；構成 IKEv2、TLS 1.3、Noise IK 的學術根基。

## Problem
1992 STS（Diffie-Oorschot-Wiener）試圖用「簽完整 transcript」加進 DH 達成認證。後續發現 STS 有 UKS (Unknown Key Share) 漏洞——兩端認為跟對方有共享 key 但各自註冊的對方身份不一致。1990s ISO 標準與 IKEv1 各自打補丁但都不漂亮。需要一個 modular、可證明、且支援 identity protection 的 AKE 設計。

## Contribution（綜合 abstract + 訓練資料 + 標準的常識）
1. **SIGn-and-MAc 結構**：
   ```text
   Round 1: A → B: g^a, ID_A?
   Round 2: B → A: g^b, ID_B, MAC_K(ID_B), Sign_B(g^a, g^b)
   Round 3: A → B: ID_A, MAC_K(ID_A), Sign_A(g^b, g^a)
   ```
   關鍵 insight：**簽章只簽 DH share 對 (g^a, g^b)**，identity 不放進簽章而靠 MAC 綁定；session key K 從 g^(ab) 派生。
2. **解決 UKS**：MAC 把 identity 跟 session key 綁定——對手即使能 substitute identity 也不能讓 MAC verify。
3. **提供 KCI Resistance**：取得 A 的 LTK 不能讓對手假冒**任何別人**對 A，因為 MAC 涉及 fresh DH，對手算不出。
4. **SIGMA-I (identity protection)**：第二、三 round 的 ID 與 signature 用 K 加密 → 被動觀察者看不到雙方身份。被 TLS 1.3 ServerHello 之後的 EncryptedExtensions/Certificate 直接繼承。
5. **SIGMA-R (4-round)**：把 responder 身份揭露順序倒過來，達成 responder identity protection。
6. **形式化證明**：在 Canetti-Krawczyk 2001 model 下證明 secrecy + mutual auth + KCI-resistance + UKS-resistance + Wpfs (weak forward secrecy)。

## Method
SIGMA-I 的握手（簡化版）：

```text
A → B: g^a, [ID_A?]
B → A: g^b, ENC_K0( ID_B, Sign_B(g^a, g^b), MAC_K1(ID_B) )
A → B: ENC_K0( ID_A, Sign_A(g^b, g^a), MAC_K1(ID_A) )

K0 = KDF(g^ab, "enc")
K1 = KDF(g^ab, "mac")
K_session = KDF(g^ab, "session")
```

**為什麼簽 (g^a, g^b) 而不是整個 transcript**：簽 transcript 看似更安全但會引入 UKS（簽章本身不綁 identity；對手能讓 A 簽一個會在不同 session 中 verify 通過的 (g^a, g^b)）。簽 DH share + MAC binding identity 是最小可行的 binding。

**TLS 1.3 對應**：ClientHello/ServerHello 對應 (g^a, g^b)；Certificate + CertificateVerify 對應 Sign；Finished message 對應 MAC（綁定 transcript hash）。所以 RFC 8446 才在 Section 4.4.4 明確說「Finished is essentially a MAC over the transcript」。

## Results
- IKEv2 (RFC 7296) 的 signature mode 直接採用 SIGMA。
- TLS 1.3 (RFC 8446) 的 handshake 是 SIGMA-I 變體。
- Noise IK pattern (Perrin 2018) 是 SIGMA 的 PSK + 1-RTT 變體。
- WireGuard 用 Noise IK，間接繼承 SIGMA 思想。

## Limitations / what they don't solve
- 不直接支援 PCS——session key 一旦從 g^(ab) 派生就 fix；要 PCS 需另外加 ratchet。
- 對 0-RTT data 沒處理。
- PSK-only 模式（無 DH）需要另外設計（Noise NK / NN）。

## How it informs our protocol design
- **Proteus 握手用 SIGMA-I 結構**：ephemeral X25519 + Ed25519 簽 DH share pair + HMAC bind identity + identity protection via early-derived encryption key。
- **Proteus transcript 必須包含 ciphersuite list**：防 downgrade（Logjam 2015 的 lesson）。
- **Proteus spec 證明採用 CK^+ model**：直接 reference SIGMA security 證明。

## Open questions
- SIGMA 在 PQ-hybrid 下的精確 security model 仍在收斂（Bos 等 2023）。
- SIGMA + 0-RTT 的精確 PCS 邊界 open。

## References worth following
- Canetti, Krawczyk *Analysis of Key-Exchange Protocols and Their Use for Building Secure Channels* (EUROCRYPT 2001) — CK model 原文。
- Diffie, Oorschot, Wiener *Authentication and Authenticated Key Exchanges* (Designs, Codes and Cryptography 1992) — STS protocol（SIGMA 修正的對象）。
- Bhargavan et al. *Implementing and Proving the TLS 1.3 Record Layer* (IEEE S&P 2017) — TLS 1.3 跟 SIGMA 的 formal mapping。
- Perrin *The Noise Protocol Framework* (revision 34, 2018) — Noise patterns 與 SIGMA 的 family resemblance。
