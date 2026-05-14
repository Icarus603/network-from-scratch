# Lucky Thirteen: Breaking the TLS and DTLS Record Protocols
**Venue / Year**: IEEE S&P 2013，pp. 526–540（19 May 2013）
**Authors**: Nadhem J. AlFardan, Kenneth G. Paterson（ISG, Royal Holloway, University of London）
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: PDF 開放（ieee-security.org/TC/SP2013/papers/4977a526.pdf）
**One-line**: CBC + HMAC（MAC-then-encrypt）的 timing distinguisher——「13 bytes」是 HMAC-SHA1 inner pad 邊界的吉利數字；攻擊把 Vaudenay 2002 的 padding oracle 從「明顯 alert」升級到「微秒級 timing 差」。

## Problem
- TLS RFC 規範：解 CBC 失敗時要在「bad padding」與「bad MAC」之間 indistinguishable
- 但 implementation 為了過 MAC 必須先剝 padding；若 padding bad，HMAC 仍要 run constant time
- HMAC 內 block boundary 在 message length 13 bytes 跨界 → run time 多一個 SHA-1 block (~MAC 內 1 個 64-byte block)
- 攻擊者統計 server 回應 timing 即可 distinguish bad padding vs bad MAC，恢復 padding oracle

## Contribution
1. **distinguishing attack** + **plaintext recovery attack**（與 BEAST 一脈，但作用在 record layer 而非 IV）
2. **OpenSSL、GnuTLS、NSS** 都被 PoC 驗證
3. **DTLS 也適用**——而且 DTLS 沒 alert close，可以多次 query 同一 record
4. **Paterson-Ristenpart-Shrimpton (ASIACRYPT 2011)** 的 TLS record 安全證明 assumption 被打破：proof 假設 attacker 無法 distinguish 失敗原因，這篇證明 timing 就是 distinguisher

## Method (just enough to reproduce mentally)
- Active MITM 截獲 cookie-bearing record，cut/paste 到自己控制的 record 結構中
- Resubmit 到 server，量 timing
- 透過 padding byte 結構（PKCS7-like）逐 byte 推 plaintext

## Results
- ~2^23 sessions 可恢復一個 cookie byte（實驗 setting 內）
- 推動 OpenSSL 1.0.1d / GnuTLS 3.1.7 等緊急 patch（CVE-2013-0169）
- 後續 OpenSSL 引入「constant-time CBC decrypt」實現，但 implementation 極其脆弱（Yarom 等後續仍能 break）

## Limitations / what they don't solve
- 攻擊需要 active 且能誘發大量 sessions（cookie-bearing JS in browser 配合）
- 不 work on AEAD
- Constant-time mitigation 在 cache 層仍可能被 Flush+Reload 打

## How it informs our protocol design
- **AEAD only**（fused EtM 完全規避這條 oracle）
- **timing side channel 要 spec 層討論**：spec 必須說「失敗路徑必須 constant-time」並指明 candidate implementation
- **變長 padding 需獨立 length-hiding 機制**（不能依賴 MAC + padding 的 ordering）

## Open questions
- 後續 cache-based side channel（Flush+Reload, Prime+Probe）對 record layer 仍有威脅，是否能在 constant-time AEAD 下完全消滅？目前 ring / s2n 等 implementation 用 SIMD constant time 加 secret-independent control flow，但 formal verify 困難

## References worth following
- Vaudenay. *Security Flaws Induced by CBC Padding*. EUROCRYPT 2002 — 起源
- Canvel et al. *Password Interception in a SSL/TLS Channel*. CRYPTO 2003 — TLS 1.0 timing 第一次
- Bardou et al. *Efficient Padding Oracle Attacks on Cryptographic Hardware*. CRYPTO 2012

---

**用於課程**：Part 4.1（為何 1.3 拿掉 CBC）、Part 3.8（AEAD vs MtE）、Part 9（timing side channel 在 censorship context）
