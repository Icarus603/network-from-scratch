# Selfie: reflections on TLS 1.3 with PSK
**Venue / Year**: IACR ePrint 2019/347（2019）；期刊版 *Journal of Cryptology* 34:27, 2021
**Authors**: Nir Drucker, Shay Gueron（University of Haifa / Amazon AWS）
**Read on**: 2026-05-14 (in lessons 4.1, 4.5)
**Status**: ePrint 開放；HTML abstract 完整；PDF 暫無下載（IACR 開放）
**One-line**: 第一個 post-RFC TLS 1.3 結構性攻擊——formal proof 漏掉了「PSK 沒有 role binding」這條，導致 reflection attack 把同一個 endpoint 拐成自己跟自己 handshake。

## Problem
- TLS 1.3 external PSK 模式（`psk_ke` / `psk_dhe_ke`）讓兩端用 out-of-band 共享 secret 跳過 cert 驗證
- 安全假設「PSK 只在兩個 honest party 之間共享」
- 但若 PSK 在 group 中或在自己跟自己（pair (A, A) 雖然奇怪但 spec 沒禁）共享，handshake 沒任何欄位告訴 server「對方應該是 client 而不是另一個 server」
- TLS 1.3 spec 沒強制 role binding

## Contribution
1. **Selfie attack 形式化呈現**：active MITM 把 A 跑出的 ClientHello 直接送回 A，A 以為自己是 server 收到 client，但 A 同時也跑 client 角色 → 反射攻擊
2. **OpenSSL 實證**：實作 PoC 顯示 Selfie 真的能在 OpenSSL TLS 1.3 PSK 模式下完成 handshake
3. **Formal model gap 補丁**：擴充 Dowling et al. multi-stage key exchange (MSKE) model，加入「role binding 是必要 assumption」這條，重新證 PSK 模式的 secrecy + authentication
4. **指出**：先前 Bhargavan/Cremers 等人的 1.3 formal proof 在這條 assumption 上是 implicit，導致漏網

## Method (just enough to reproduce mentally)
- A holds PSK shared with itself (or a group)
- Attacker forwards A 的 ClientHello → A 的另一個 listening port
- A 的 server 角色用同一個 PSK 驗證，產出 ServerHello + ClientFinished 之後接受連線
- 兩個 session 共享同一條 key schedule → attacker 可以路由 inner traffic 在兩個方向上構造矛盾語意

## Results
- 對 `psk_ke` 與 `psk_dhe_ke` 兩種 mode 都成立
- 在 group-PSK 部署（IoT 場景常見）裡威脅尤其大
- 修補建議：spec 應強制「PSK 對應的兩端 identity 各自被 hash 進 PSK derivation」或 spec 強制 mutual external authentication

## Limitations / what they don't solve
- 攻擊不影響 cert-based handshake
- 對單一 (client, server) 對的 PSK 部署，若雙方真的 distinct identity，影響有限——但 spec 沒任何欄位區分
- 攻擊 surface 是 deployment + spec 互動，不是密碼學原語的問題

## How it informs our protocol design
- **Role binding 必須在 spec level 強制**：我們協議的 handshake 把 "I'm initiator / I'm responder" 寫進 transcript hash 並 PSK-derive
- **External PSK 對應的 identity 必須 first-class field**：不能讓 PSK 變成隱式 group secret
- **Formal model 必須包含 role attribute**：Part 5 的 ProVerif/Tamarin 建模時要把 role 寫成 predicate

## Open questions
- 在 hybrid post-quantum PSK + Kyber 場景下，role binding 是否需要重新證？
- Selfie 是否泛化到其他 PSK protocols（IKEv2, Noise IK）？Noise 規格明確 binds initiator/responder 到 chaining key，所以無 Selfie——但這值得在 Part 5 對比

## References worth following
- Dowling, Fischlin, Günther, Stebila. *A Cryptographic Analysis of the TLS 1.3 Handshake Protocol*. *Journal of Cryptology* 2021（multi-stage key exchange model 原始 paper）
- Cremers, Horvat, Hoyland, Scott, van der Merwe. *A Comprehensive Symbolic Analysis of TLS 1.3*. CCS 2017
- Bhargavan, Blanchet, Kobeissi. *Verified Models and Reference Implementations for TLS 1.3*. S&P 2017

---

**用於課程**：Part 4.1（1.3 仍有 corner case）、Part 4.5（PSK + 0-RTT）、Part 5.4-5.6（formal proof 模型如何漏掉 role binding）
