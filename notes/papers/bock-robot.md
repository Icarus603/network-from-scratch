# Return Of Bleichenbacher's Oracle Threat (ROBOT)
**Venue / Year**: USENIX Security 2018
**Authors**: Hanno Böck (Hackmanit), Juraj Somorovsky (Ruhr-Universität Bochum / Hackmanit), Craig Young (Tripwire VERT)
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: robotattack.org overview 完整；論文 PDF 下載到 assets/papers
**One-line**: Bleichenbacher 1998 在 2018 還活著，因為「我們已經修了」的話從來沒被 implementation 真正執行——只要還有 RSA-KE，就還有 oracle。

## Problem
- TLS 1.2 仍允許 RSA-based key exchange ciphersuites（RFC 5246 §7.4.7.1）
- 1998 以來每次「修補」都是 implementation-level patch（TLS 1.0 §7.4.7.1 推薦 Bleichenbacher countermeasure）
- 但 countermeasure 要求**所有錯誤路徑 timing/bytes 完全一致**——實作上幾乎不可能

## Contribution
1. **Fingerprint 8+ 個 server 對 Bleichenbacher oracle 的不同錯誤回應 pattern**（TLS alert、connection close timing、TCP RST、handshake fail mode）
2. **Internet-scan 確認 vulnerable vendors**：Facebook、PayPal、27 of Alexa top 100；F5 BIG-IP、Citrix NetScaler、Cisco ACE/ASA、Radware、Bouncy Castle、Erlang、WolfSSL、Palo Alto、IBM GSKit、Cavium、Symantec、Unisys ClearPath MCP、FortiGuard
3. **真實復現**：取得 facebook.com 私鑰簽章能力（簽 chosen message — 不是 cert decrypt 本身但同樣致命）

## Method (just enough to reproduce mentally)
- Client 發起 TLS 1.2 RSA-KE handshake，ClientKeyExchange 帶 chosen-RSA-ciphertext
- 觀察 server 回應：是 immediate Alert、是 deferred Alert、是 connection close、是 TCP RST、是 timing 差
- 任何「可區分」的回應就是 oracle bit
- 用 Bleichenbacher 1998 演算法 + Bardou 2012 改進（fewer queries）→ 每 PreMasterSecret 約 2^17 queries

## Results
- 8 個 distinct oracle pattern 各對應一群 vendor
- 多家 ADC / load-balancer 廠商發 CVE：CVE-2017-13099（Erlang）、CVE-2017-17428、CVE-2017-12373 …
- **不對稱影響**：簽 chosen message → 偽造任何 TLS server identity 的訊息；解被動截獲的 traffic
- 推動產業重新檢視 RSA-KE 並加速 TLS 1.3 adoption

## Limitations / what they don't solve
- ECDHE / DHE 連線完全不受影響——這也是 TLS 1.3 直接拿掉 RSA-KE 的關鍵理由
- 對 ROBOT-resistant 的 implementation 仍可能有更隱晦的 timing/cache side channel（後續論文持續發現）

## How it informs our protocol design
- **RSA-KE 不存在於我們協議的 spec**——這是 hard rule
- 任何 KEM 採用都用 **explicit reject path**，且 reject 路徑與 accept 路徑在 timing/memory/log 上完全 indistinguishable（constant-time decode）
- Spec **明寫** countermeasure 行為——不允許 implementation 各自詮釋

## Open questions
- 在後量子 KEM 場景下（Kyber/ML-KEM 也有 implicit rejection），是否能複製 ROBOT 的「8 種 fingerprint」攻擊？
- Server 端的 implementation-level constant-time guarantee 怎麼 verify？目前 LibSignal、ring 等用 audit + ctgrind / dudect，但無 formal spec-level 保證

## References worth following
- Bleichenbacher (CRYPTO 1998) — origin
- Bardou et al. *Efficient Padding Oracle Attacks on Cryptographic Hardware*. CRYPTO 2012 — query reduction
- Meyer et al. *Revisiting SSL/TLS Implementations: New Bleichenbacher Side Channels and Attacks*. USENIX Security 2014 — 預示 ROBOT
- TLS 1.3 RFC 8446 §1.3：明確列出「RSA Key Exchange is removed」為 1.3 主要改動

---

**用於課程**：Part 4.1（TLS 死亡史）、Part 3.10（PKCS#1 v1.5 padding oracle）、Part 4.2（為何 1.3 拿掉 RSA-KE）
