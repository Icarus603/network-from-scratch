# A Symbolic Analysis of Privacy for TLS 1.3 with Encrypted Client Hello
**Venue / Year**: ACM CCS 2022, pp. 365–379. DOI: 10.1145/3548606.3559360
**Authors**: Karthikeyan Bhargavan（Inria / Cryspen）, Vincent Cheval（Inria）, Christopher A. Wood（Cloudflare / Cryspen）
**Read on**: 2026-05-14 (in lesson 4.6)
**Status**: ACM 開放摘要；full PDF 透過 Cloudflare research page 可索取；下載失敗——記為 abstract-only
**One-line**: ECH 的第一個 mechanized privacy proof，用 ProVerif 把「passive 與 active observer 對 server identity 的可區分性」形式化為 indistinguishability lemma，並在過程中發現 ESNI draft-00 的 cut-and-paste attack。

## Problem
- TLS 1.3 已修補 confidentiality 與 authentication，但 **privacy** (specifically server name leakage) 還是個 open problem
- 早期 ESNI draft 只加密 SNI extension，其他 ClientHello 仍明文 → cut-and-paste replay attack
- 多輪 draft 演化（ESNI → ECH）改進在每輪都被新 attack 發現；缺乏 formal privacy framework

## Contribution
1. **第一個 mechanized formal privacy model for TLS 1.3 with ECH**
2. ProVerif (applied pi calculus) 形式化 server identity privacy 為 observational equivalence
3. 發現多個 ECH draft 的 attack：
   - ESNI draft-00 cut-and-paste replay
   - 早期 ECH 的 outer/inner mix-and-match
4. 引導 IETF TLS WG 修正 ECH spec — 最終 spec 把整個 inner ClientHello 加密 + HPKE AAD binding outer
5. **最大規模 ProVerif privacy proof** 之一，可作為其他 protocol 模板

## Method
- ProVerif applied pi calculus 建模 TLS 1.3 + ECH 所有 mode
- Privacy property = observational equivalence under attacker：把「真實 server name = A」與「真實 server name = B」兩個 process 對 attacker indistinguishable
- 引入 anonymity set 概念：privacy 是相對的，只在「outer SNI 對應 server set 內」成立

## Results
- 證明：spec 最新版（當時 draft-15+）的 ECH 對 passive observer 提供 server name privacy
- 證明：對 active on-path attacker, ECH 仍提供 server name privacy（前提：HPKE AEAD 安全 + outer SNI 對 anonymity set 一致）
- 揭示：privacy 對 anonymity set 為 1 時 trivially 無效 — 必須有 nontrivial set of servers fronting under same outer SNI
- TLS implementors 操作建議：在 ECH config 中如何宣告 anonymity set

## Limitations
- Symbolic model：密碼學原語視為 ideal
- 不能 cover 流量分析（packet timing, size）攻擊 — Part 10 詳
- 不討論 deployment 真實 anonymity set — Cloudflare 等 CDN 才能真正提供

## How it informs our protocol design
- **Privacy ≠ confidentiality**: 我們協議的 spec 必須有 privacy 條款，且形式化
- **Anonymity set 必須在 spec 強制**: 不能讓 deployment 出現 anonymity set = 1 的情況
- **HPKE AAD binding 是 inner/outer 防 mix-and-match 的關鍵**
- 採用同樣 ProVerif 流程做我們協議的 privacy proof（Part 11.10 + Part 12）

## Open questions
- ECH 在 metadata-rich 場景（CDN multi-tenant）下 anonymity set 怎麼維護
- ECH + 0-RTT 的 privacy 互動 (本 paper 未涵蓋)
- ECH + traffic shaping 的 indistinguishability 形式化

## References worth following
- HPKE: RFC 9180
- draft-ietf-tls-esni-22 最新版
- Cremers et al. 2017 CCS Tamarin TLS 1.3 — 前置 work

---

**用於課程**：Part 4.6（ECH 形式化）、Part 5.4–5.6（ProVerif）、Part 11.10（privacy proof 流程）
