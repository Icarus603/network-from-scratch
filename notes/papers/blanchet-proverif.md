# An Efficient Cryptographic Protocol Verifier Based on Prolog Rules
**Venue / Year**: 14th IEEE Computer Security Foundations Workshop (CSFW-14), 2001, pp. 82–96. **Test of Time Award** at CSF 2023.
**Authors**: Bruno Blanchet（INRIA Rocquencourt → INRIA Paris）
**Read on**: 2026-05-14 (in lessons 5.4, 5.5)
**Status**: ePrint 開放; tutorial book *Modeling and Verifying Security Protocols with the Applied Pi Calculus and ProVerif* (Foundations and Trends 2016) ~100 頁；已下載到 assets/papers/foundations-2016-blanchet-proverif.pdf
**One-line**: 用 Horn clauses + resolution algorithm 對 applied pi-calculus protocol 自動證 secrecy / authentication — unbounded sessions, fast — 成為 TLS / Signal / Noise / WireGuard 等 protocol verification backbone。

## Problem
- 1990s 末 model checker (FDR, Murphi) 對 small N sound, 但**對 unbounded sessions 不能 verify**
- 真實 protocol 必須對 attacker 在 unbounded number of sessions 安全
- 需要 abstraction 機制讓 verification 對 unbounded scale extend

## Contribution
1. **Horn clause abstraction of applied pi-calculus**: protocol step → clauses `att(M1) /\ ... /\ att(Mn) ⇒ att(M)` 
2. **Resolution algorithm**: 對 goal `att(secret)` 試 derive — 找不到 derivation → secret 安全
3. **Unbounded sessions support**: replication `!P` 自然 model
4. **Speed**: 多數 AKE protocol 秒級 verify
5. **Attack reconstruction**: 從 derivation tree reconstruct concrete attack trace

## Method
- Applied pi-calculus spec (process syntax) → ProVerif compiler 自動 abstract 成 Horn clauses
- Cryptographic primitives 用 `fun` + `reduc` 寫 equational theory
- `query attacker(M)`: 查 attacker 能否 derive M
- `query event(A) ==> event(B)`: 查 authentication correspondence
- Resolution-based saturation 解 derivation question

## Results
- 100+ protocol 已 verified using ProVerif:
  - TLS 1.3 (Bhargavan-Blanchet-Kobeissi S&P 2017)
  - Signal X3DH + Double Ratchet (Kobeissi-Bhargavan-Blanchet 2017)
  - WireGuard / Noise IK (Lipp-Blanchet-Bhargavan EuroS&P 2019)
  - MLS (Cremers et al.)
  - ECH (Bhargavan-Cheval-Wood CCS 2022)
- Industry adoption: AWS s2n-tls, Cloudflare quiche partial coverage
- **Test of Time Award at CSF 2023** 認可 22 年持續貢獻

## Limitations / what they don't solve
- **Horn clause over-approximation**: 偶有 false positive (attack 標記但實際不可達)
- **Stateful protocol awkward**: anti-replay window 等需 GSVerif extension
- **No probability / computational**: 純 symbolic; CryptoVerif (same author) 補 computational
- **Termination not guaranteed**: 複雜 protocol 可能跑不完
- **XOR equation 處理弱**

## How it informs our protocol design
- **ProVerif 是我們協議 symbolic secrecy / authentication 主工具**
- **Applied pi-calculus 表達 protocol 直觀**: 對 protocol designer learning curve moderate
- **Pattern**: 先 ProVerif (fast, broad) → 找 corner case 用 Tamarin (slower, more expressive)
- **Annotated correspondence to spec** 必須維護

## Open questions
- **Hybrid symbolic-computational verification**: 目前 manual orchestration
- **Stateful protocol full automation**: GSVerif 部分解, 仍 active research
- **Quantum adversary in ProVerif**: 部分 extension, 未 mainline

## References worth following
- Blanchet *Foundations and Trends* 2016 tutorial (~100 pages, **必讀**)
- Abadi & Fournet POPL 2001 *Mobile Values, New Names, and Secure Communication* — applied pi-calculus 起源
- Blanchet IEEE TDSC 2008 *CryptoVerif* — computational counterpart
- Cheval-Cortier-Turuani CCS 2018 *GSVerif* — stateful extension
- Kobeissi-Bhargavan-Blanchet EuroS&P 2017 *Noise Explorer* origins

---

**用於課程**：Part 5.4 (ProVerif core)、Part 5.5 (Noise IK / WireGuard 應用)、Part 11.10 (我們協議 secrecy/auth proof)
