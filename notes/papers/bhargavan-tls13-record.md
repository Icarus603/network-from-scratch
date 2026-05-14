# Implementing and Proving the TLS 1.3 Record Layer
**Venue / Year**: IEEE S&P 2017（May 2017），pp. 463–482，DOI: 10.1109/SP.2017.58。 IACR ePrint 2016/1178 為 full version
**Authors**: Antoine Delignat-Lavaud, Cédric Fournet, Markulf Kohlweiss, Jonathan Protzenko, Aseem Rastogi, Nikhil Swamy, Santiago Zanella-Béguelin, Karthikeyan Bhargavan, Jianyang Pan, Jean Karim Zinzindohoué（PROSECCO / Microsoft Research / Edinburgh）
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: ePrint 完整；project-everest.github.io/record/ 有後續工具鏈
**One-line**: 第一個對 TLS 1.3 record layer 同時驗 *functional correctness* + *cryptographic security* 的論文——用 F* 把 AEAD、Poly1305/GHASH、length-hiding 全證一遍，並接上 miTLS。

## Problem
- TLS 1.3 record layer 是 sub-protocol（handshake / alert / appdata / 0-RTT / 0.5-RTT）的多工器，需要 AEAD-based stateful encryption + padding length-hiding + content-type hide
- 舊 TLS 1.0–1.2 record 設計散落於十幾個 ciphersuites，無統一模型
- 1.3 提出統一 AEAD construction 但 spec prose 無法保證 implementation 對齊

## Contribution
1. **AEAD 通用安全證明**：用任何 secure one-time MAC（Poly1305 或 GHASH）+ PRF 構造，給 IND-CPA + INT-CTXT 上界
2. **Stream encryption → length-hiding multiplexed encryption** 的分層歸約
3. **TLS 1.3 record layer 對 adversary controlling sub-protocols 的安全模型**
4. **AES-128-GCM / AES-256-GCM / CHACHA20-POLY1305 具體 bound** → 建議 rekey 上限（這是 RFC 8446 §5.5 後來成為 spec 的 source）
5. **可執行的 verified implementation**：F* → KreMLin → C，整合進 miTLS，與 Chrome/Firefox interop
6. **HACL\* cryptographic library 雛形**（之後變成 Project Everest 主要交付物）

## Method (just enough to reproduce mentally)
- F* 同時是 implementation 語言 + spec 語言；refinement type 表達 functional correctness
- 安全屬性以 game-based definition 寫成 F* code（attacker = arbitrary F* function with bounded complexity）
- 用 KreMLin 把 F* 編譯到 portable C（後來 OpenSSL/Mozilla 在 TLS handshake 部分採用過 HACL\*）

## Results
- TLS 1.3 record layer **provably secure** 且**有 verified implementation**
- 為 RFC 8446 草案 21 → final 提供具體 rekey limit（AES-GCM ~2^24.5 records before rekey）
- HACL\* 至今仍是 Mozilla NSS / Linux kernel 部分採用的 verified cryptographic library

## Limitations / what they don't solve
- 只證 record layer；handshake 由同團隊另一篇（Bhargavan-Blanchet-Kobeissi S&P 2017）證
- F\* 證明在 symbolic AEAD ideal model 上；implementation-level side channel（timing, cache）需 ctgrind 等補充
- 0-RTT replay 風險不在 record layer 模型內

## How it informs our protocol design
- **AEAD-only**：我們協議直接套這個模型，不發明新 record
- **Rekey limit 必須 spec 寫進**：不能讓 implementation 自由決定（Part 11.6 詳）
- **Verified implementation 是長期目標**：Part 12 我們的 SOTA 協議至少 record layer 要能用 HACL\* 替換

## Open questions
- 1.3 record layer 的 padding 對 length side channel 保證有限（Part 4.4 / Part 10 詳）
- Length-hiding 對 traffic analysis 的實效有多少？這是 Part 10 的核心問題

## References worth following
- Project Everest：https://project-everest.github.io/
- HACL\*：https://github.com/hacl-star/hacl-star
- F\*：https://www.fstar-lang.org/

---

**用於課程**：Part 4.1（formal verification 範式）、Part 5.7（CryptoVerif）、Part 5.5（miTLS）、Part 4.3（record layer 細節）
