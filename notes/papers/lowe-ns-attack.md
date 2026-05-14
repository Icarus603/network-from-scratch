# Breaking and Fixing the Needham-Schroeder Public-Key Protocol Using FDR
**Venue / Year**: TACAS 1996, LNCS 1055, pp. 147–166
**Authors**: Gavin Lowe（Oxford University Computing Laboratory）
**Read on**: 2026-05-14 (in lesson 5.1)
**Status**: PDF 開放（Springer + 多個 mirror）；已下載到 assets/papers/tacas-1996-lowe-ns.pdf
**One-line**: 用 FDR (CSP refinement checker) 對 1978 年 Needham-Schroeder PK protocol 發現 17 年沒人看到的 man-in-the-middle attack — 開啟 mechanized protocol verification 紀元。

## Problem
- Needham-Schroeder 1978 PK protocol 用三步 nonce exchange 達 mutual authentication
- 業界視為 textbook authenticated key exchange，被寫進無數教科書
- 1978-1995 期間人工 review 都沒發現 attack
- 但缺乏 mechanical verification

## Contribution
1. **發現 17 年潛伏的 MITM attack**: interleaved two-run scenario, attacker impersonates Alice to Bob
2. **NSL fix**: 在 message 2 加 responder identity (Bob's pubkey) 防止 Alice misinterpret responder
3. **FDR application to security protocol**: 第一個重要 protocol verification 用 mechanical model checker
4. **「Small system ⇒ arbitrary size」 lemma**: 對 well-formed protocol, 模 N=2 sound 即 N=∞ sound

## Method
- **CSP (Communicating Sequential Processes)** model agents + intruder
- **FDR (Failures-Divergences Refinement)** 1995 開發, 對 small instance enumerate trace
- 對「spec process」與「impl process」做 refinement check
- Spec = expected authentication property; impl = NS protocol; attack = refinement violation

## Results
- 在 N=2 honest agent + 1 intruder small instance 找到 attack trace
- Attack trace 對應實際 wire-level message exchange
- NSL fix 後 FDR no longer find attack
- 證 size-2 result lift to arbitrary size for this class of protocol

## Limitations / what they don't solve
- **Pre-CSP era tools 對 unbounded sessions 困難**
- **Equational theory limited**: 不支援 DH 等 algebraic structure
- **No computational reasoning**: 純 trace-level

## How it informs our protocol design
- **mechanized verification 不是 optional**: 17 年人工 review 都沒抓到 bug, 工具用一天找到
- **Authentication property 必須形式化**: Lowe 1997 follow-up paper 給 4 層 hierarchy 是 design 必須清楚 commit 的
- **「Spec evolution + verification 同步」**: 我們協議每次 spec 改動必須 re-verify

## Open questions
- 對更 complex protocol (multi-stage AKE, group key exchange), FDR-style tools 仍 limited
- Lowe 1996 之後 30 年, formal verification 仍未變 mainstream — 為何 industry adoption rate slow?

## References worth following
- Burrows-Abadi-Needham 1990 *A Logic of Authentication* (BAN logic, 前身 attempt)
- Lowe 1997 *A Hierarchy of Authentication Specifications* (CSFW)
- Meadows *NRL Protocol Analyzer* 1996
- Mitchell *Murphi* 1997
- 此後一連串自動化 tools 演化到 ProVerif, Tamarin

---

**用於課程**：Part 5.1（formal verification 必要性的最 striking 案例）
