# A Comprehensive Symbolic Analysis of TLS 1.3
**Venue / Year**: ACM CCS 2017，pp. 1773–1788。DOI: 10.1145/3133956.3134063
**Authors**: Cas Cremers（Oxford / CISPA）, Marko Horvat（MPI-SWS）, Jonathan Hoyland（Royal Holloway）, Sam Scott（Royal Holloway）, Thyla van der Merwe（Royal Holloway）
**Read on**: 2026-05-14 (in lessons 4.1, 5.6)
**Status**: preprint PDF 開放（acmccs.github.io/papers/p1773-cremersA.pdf）；Tamarin source files https://tls13tamarin.github.io/TLS13Tamarin/
**One-line**: 用 Tamarin Prover 對 TLS 1.3 draft 21 構造「最完整、最忠實、最模組化」的 symbolic model，並找出 PSK + 0-RTT 模式下的非預期 authentication 退化行為。

## Problem
- TLS 1.3 draft 進度極快（draft 10 → 21 之間 PSK 結構與 0-RTT 機制大改）
- 同團隊 IEEE S&P 2016 paper 已對 draft 10 做過 symbolic analysis；draft 10 後又改了 11 版
- 需要重新證 draft 21 的 secrecy / authentication / key independence / FS / PCS / unique session keys 等所有安全屬性

## Contribution
1. **完整 Tamarin model**：handshake、key schedule、0-RTT、0.5-RTT、PSK、HelloRetryRequest、post-handshake auth、KeyUpdate、Application Data 全建模
2. **8 種安全屬性逐一證明**（secret keys, authentication, key independence, perfect FS, …）
3. **發現 non-injective authentication**：在某些 PSK 模式下，server 可能對「同一個 client」接受兩個 distinct authentication context，被視作 spec-level 隱性問題
4. **annotated RFC**：把 prose RFC 跟 Tamarin rules 一一對齊，成為後續形式化驗證 community 的 reference workflow

## Method (just enough to reproduce mentally)
- Tamarin = multiset rewriting + first-order logic + heuristic backward search
- 每個 protocol message 用 multiset rewriting rule 表示 state transition
- 安全 property 寫成 first-order temporal logic（trace properties + observational equivalence）
- 由 Tamarin 自動 / 半自動 search proof tree（部分屬性需要人工 lemma）

## Results
- **大部分 1.3 安全屬性在 draft 21 成立**（secrecy, FS）
- **發現 PSK + post-handshake auth 的某些 corner case** 推動 spec 修正（後續成為 1.3 final 的明文 restriction）
- Tamarin source files 後被多篇 follow-up paper（包括 ECH 的 2022 CCS 形式化分析）拿來當基礎

## Limitations / what they don't solve
- Symbolic model：密碼學原語視為 ideal（perfect hash、no collisions、no algebraic attacks）
- 不能捕捉 timing side channel、padding oracle 之類的 implementation-level attack
- 不證明計算複雜度 bound（要 CryptoVerif，Part 5.7）

## How it informs our protocol design
- **新協議的 Part 11.10**：我們把 Tamarin model 視為 spec 的一部分共同 release
- **跟 RFC prose 對齊的 annotated source** 是 best practice：spec change 之後第一件事是更新 Tamarin
- **PSK + 0-RTT 是高危區**：Part 4.5 詳講

## Open questions
- 在 hybrid PQ 加進 1.3 之後，Tamarin model 是否需要重證？目前社群（特別是 Cremers 組）正在做
- TLS 1.3 + ECH 的 privacy property 是 observational equivalence，需要新 Tamarin techniques

## References worth following
- Cremers et al. *Automated Analysis and Verification of TLS 1.3: 0-RTT, Resumption and Delayed Authentication*. IEEE S&P 2016
- Bhargavan-Blanchet-Kobeissi *Verified Models and Reference Implementations for the TLS 1.3 Standardization Candidate*. S&P 2017
- Arfaoui et al. *A Symbolic Analysis of Privacy for TLS 1.3 with Encrypted Client Hello*. CCS 2022 — Part 4.6 ECH 必讀

---

**用於課程**：Part 4.1（formal verification 範式）、Part 5.6（Tamarin）、Part 4.5（PSK + 0-RTT 形式化）
