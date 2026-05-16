# The Dangers of Key Reuse: Practical Attacks on IPsec IKE
**Venue / Year**: USENIX Security 2018
**Authors**: Dennis Felsch, Martin Grothe, Jörg Schwenk (Ruhr-University Bochum); Adam Czubak, Marcin Szymanek (University of Opole)
**Read on**: 2026-05-16 (in lesson 6.1)
**Status**: full PDF (`assets/papers/felsch-ipsec-ike-2018.pdf`)
**One-line**: 利用「IKEv1 與 IKEv2 共用同一把 RSA long-term key」這個架構性瑕疵，把 IKEv1 的 Bleichenbacher oracle 投射成 IKEv2 簽章認證的 bypass。

## Problem
IKE 規格允許多種 authentication method：PSK、RSA signature、RSA encrypted nonces、ECDSA。IKEv1 與 IKEv2 共享同一張 ID/key database。沒人系統性檢查過：跨版本、跨 auth-method 重用 long-term key 是否安全。

## Contribution
1. **發現 IKEv1 RSA encrypted-nonces auth-mode 的 Bleichenbacher oracle**：responder 對 INVALID_KEY_INFORMATION notify 訊息的回應時間差異洩漏 PKCS#1 v1.5 padding validity。
2. **把這個 oracle 用來 forge IKEv2 RSA signature**：因為 RSA-PKCS1.5 簽章與 RSA-PKCS1.5 加密的「padding 解析」邏輯非常接近，oracle 可被改造成 signature forge。
3. **實際 CVE**：
   - **CVE-2018-0131** (Cisco IOS / IOS XE / ASA)
   - **CVE-2017-17305** (Huawei)
   - **CVE-2018-8753** (Clavister)
   - **CVE-2018-9129** (ZyXEL)
4. **跨 protocol authentication bypass**：等於用 IKEv1 oracle 打 IKEv2，反之亦然。
5. **延伸**：對 PSK 模式的 offline dictionary attack 也展示更高效版本。

## Method
- 對若干 vendor 的 IKE 實作做 timing measurement 與 error-response classification。
- 構造 Bleichenbacher-style adaptive chosen ciphertext attack。
- 在 lab 環境完成 full impersonation。

## Results
- 4 個 CVE，全是大廠（Cisco / Huawei / Clavister / ZyXEL）。
- 推動所有 vendor 拔掉 IKEv1 RSA-encrypted-nonces 選項。
- 推動學界重新檢視「key reuse across protocols」這個一直被忽略的攻擊面。

## Limitations / what they don't solve
- 需要 active on-path（能與 responder 建立 N 次 IKE session）。
- 對 ECDSA-only deployment 不適用。
- 不能解密過去通訊（只能 impersonate）。

## How it informs our protocol design
G6 的決定：
- **絕對禁止 key 跨 protocol / 跨 protocol version reuse**。每個 spec major version 必須有獨立的 KDF context label（類似 TLS 1.3 的 `tls13 ...` HKDF labels）。
- **PKCS#1 v1.5 全面禁用**。簽章用 EdDSA / Ed25519；KEM 用 X25519/MLKEM-hybrid。
- **無 RSA-encrypted-nonces 這種「historic curiosity」auth mode**。
- 這也是 [Part 3.7 數位簽章](../../lessons/part-3-cryptography/3.7-digital-signatures.md) 為什麼把 PKCS1.5 從 MAY 直接劃成 must-not。

## Open questions
- 是否還有其他「跨版本 protocol key reuse」漏洞潛伏？例如 OpenVPN 2.x 對 TLS 1.2/1.3 共用 cert 是否會出類似問題？
- post-quantum 階段，KEM key + signature key 是否該也獨立？（NIST PQ 推 hybrid 的時候有這個考量。）

## References worth following
- Bleichenbacher 1998 *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1*（[3.4 RSA](../../lessons/part-3-cryptography/3.4-rsa.md) 已讀）
- Aviram et al. 2016 USENIX Security *DROWN: Breaking TLS Using SSLv2*（同思想：cross-protocol key reuse）
- Böck et al. 2018 *ROBOT: Return Of Bleichenbacher's Oracle Threat*（PKCS#1 v1.5 復活鬼）
- [Part 11.5 G6 KDF 設計] 會回頭引用這篇
