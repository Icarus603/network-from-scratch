# DROWN: Breaking TLS using SSLv2
**Venue / Year**: USENIX Security 2016
**Authors**: Nimrod Aviram, Sebastian Schinzel, Juraj Somorovsky, Nadia Heninger, Maik Dankel, Jens Steube, Luke Valenta, David Adrian, J. Alex Halderman, Viktor Dukhovni, Emilia Käsper, Shaanan Cohney, Susanne Engels, Christof Paar, Yuval Shavitt
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: drownattack.com overview 完整；論文 PDF 下載到 assets/papers
**One-line**: 「20 年前禁用的 protocol」仍開著 port，就讓「20 年後 hardened 的 protocol」被被動解密——cross-protocol attack 的範式。

## Problem
- TLS 1.2 認為自己 secure，但 server 同時開 SSL 2.0 + 共用 RSA cert
- SSL 2.0 在 1996 已知有 Bleichenbacher-style padding leakage
- Attacker 截獲一段 TLS 1.2 RSA-key-exchange traffic → 用 server 的 SSLv2 endpoint 當 oracle，解 TLS 1.2 的 PreMasterSecret

## Contribution
1. **General DROWN**：~2^50 SSLv2 queries / per session → 完整解 TLS 1.2 RSA-KE 連線
2. **Special DROWN**：當 server 同時有 export-grade 弱 cipher，cost 降到 ~2^40
3. **Internet-wide scan**：33% HTTPS server (~11.5M hosts) SSLv2 reachable；7% Top 1M Alexa vulnerable

## Method (just enough to reproduce mentally)
- SSLv2 export ciphers 把 master key 切成 「11-byte secret」回傳 → 每個 SSLv2 handshake 都是一次 partial Bleichenbacher oracle
- 攻擊者**離線**對 captured TLS 1.2 ciphertext 做 Bleichenbacher 的 step-1（找 PKCS#1 v1.5 形式對的 multiplier）
- 每次 candidate ciphertext → 開一個 SSLv2 handshake，看 server 是否回 valid SSL 2 ServerVerify → oracle 答 yes/no
- 重複到 PreMasterSecret 唯一確定

## Results
- **真的**用實驗解了 OpenSSL 跑的 SSLv2 server 對應的 TLS 1.2 session
- Special DROWN 對 vulnerable 配置可在 8 小時內完成
- 推動 OpenSSL/NSS/Microsoft Schannel 緊急 patch；CVE-2016-0800

## Limitations / what they don't solve
- 純對 RSA-KE 有效；ECDHE/DHE traffic 無攻擊面（forward secrecy）
- 需要 server 既開 SSLv2 又共用 cert——是 misconfig 攻擊面，非 protocol 設計核心問題
- 但**這正是其論文價值**：證明 implementation/deployment 鏡像被動 traffic decryption 的長期風險

## How it informs our protocol design
- **不要保留舊版本**。我們的協議不設計 backward compatibility shim。
- **每個 long-term key 只承擔一個 role**。Cross-protocol oracle 風險的根源就是 key reuse across protocols。
- **不留任何「靜態 key」的 PoP**（proof of possession）路徑——任何 PoP 都應該是 ephemeral signed challenge

## Open questions
- 在後量子 KEM hybrid 場景下，是否會出現「classical KEM oracle 跨 PQ-KEM 攻擊」的 DROWN 等價？
- 部署層級的 cross-protocol attack 是否能自動掃描（Censys-style）？目前仍主要靠人工配對

## References worth following
- Bleichenbacher 1998（CRYPTO）原始 padding oracle
- RFC 6176 (2011)：formally deprecate SSL 2.0
- Heninger group 的 internet-wide TLS scan 工具鏈（zmap、zgrab）

---

**用於課程**：Part 4.1（TLS 死亡史）、Part 4.5（cross-protocol attack 警示）、Part 11.5（key separation 設計準則）
