# Attacking the IPsec Standards in Encryption-only Configurations
**Venue / Year**: IEEE Symposium on Security and Privacy (S&P) 2007
**Authors**: Jean Paul Degabriele, Kenneth G. Paterson (Royal Holloway, University of London)
**Read on**: 2026-05-16 (in lesson 6.1)
**Status**: PDF 嘗試本地化但被 Cloudflare 攔 / IACR ePrint 為 2-page stub；引用以 abstract + Pure RHUL portal 摘要為主。Full version: https://eprint.iacr.org/2007/125
**One-line**: 對 RFC-compliant 的 encryption-only ESP 做的 ciphertext-only 攻擊——把規格層級的疏漏轉成可被 GFW 類對手實際利用的密碼學災難。

## Problem
Paterson-Yau 2006 Eurocrypt 已示範 Linux 實作的 encryption-only ESP 可被破，但有人辯稱「那是實作 bug，不是規格問題」。Degabriele-Paterson 要證明：**規格本身**就破。

## Contribution
1. **三類攻擊**，皆 RFC-compliant 的 ESP encryption-only 適用：
   - **Destination-address rewriting**：把 inner IP 的 dst 改成攻擊者控制的 host，利用 IP forwarding 把解密後 payload 送到攻擊者。
   - **Protocol-field rewriting**：把 inner protocol（TCP/UDP/ICMP）的 type 改成 ICMP-echo，利用 ICMP 回應洩漏明文。
   - **Bit-flipping attack on TCP/UDP checksum**：利用 CBC malleability + checksum 驗證的差異化錯誤回應。
2. **ciphertext-only + active injection**：不需要 chosen-plaintext，只需 eavesdrop + 注入。
3. **量化評估**：對 1500-byte payload，需要 ~2^16 次注入即可恢復一個 byte。
4. **真實實作測試**：對 KAME / Openswan / Cisco IOS 都成功。

## Method
利用 IP/TCP/UDP/ICMP layer 對 malformed header 的不同錯誤回應（drop vs ICMP error vs RST），把它當 oracle 區分 ciphertext 解密後的差異化結構。

## Results
直接導致 RFC 4303 增訂強烈建議「ESP 永遠搭配 integrity」，後續 RFC 7321 / 8221 把 encryption-only 從 MAY 降到 MUST NOT 等級。但是規格上至今**沒有 hard ban**——這是 IPsec 「設計不淘汰」哲學的代價。

## Limitations / what they don't solve
- 假設 attacker 可注入封包到 victim path（多數 GFW-like 對手都能）。
- 不適用於已啟用 ESP integrity（AEAD）的部署。
- 不破 IKE，只破 ESP。

## How it informs our protocol design
Proteus 的決定：
- 連 encryption-only **選項** 都不能在 spec 留下。AEAD（ChaCha20-Poly1305）為 sole option，無 fallback。
- 不允許「下層協定的錯誤回應」作為密碼系統的可觀察 oracle——所有 decryption 失敗要 timing-constant + identical observable behavior。
- 受此論文啟發，[Part 11.4 spec 寫作守則] 列「Spec MUST NOT allow encryption-only modes」。

## Open questions
- 還有多少 IETF 規格仍含「encryption-only」legacy 選項？（CMS PKCS#7, S/MIME, JOSE encrypt 都有歷史包袱。）
- 此攻擊的延伸：對 AEAD 但有 implementation timing leak 的 ESP，類似 attack 是否仍可行？這是 Aviram-Bock 對 OpenSSL 的後續工作。

## References worth following
- Paterson & Yau 2006 Eurocrypt（前驅工作）
- Degabriele & Paterson 2010 CCS *On the (in)security of IPsec in MAC-then-Encrypt configurations*（後續 MAC-then-Encrypt 破除）
- Albrecht et al. 2009 NDSS *Plaintext recovery attacks against SSH*（同型攻擊在 SSH）
- Bellare & Namprempre 2000（generic composition 之 framework，[3.2 已讀](../../lessons/part-3-cryptography/3.2-symmetric-aead.md)）
