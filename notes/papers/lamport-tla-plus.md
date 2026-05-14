# Specifying Concurrent Systems with TLA+
**Venue / Year**: IOS Press, 1999. *Calculational System Design*, pp. 183–247
**Authors**: Leslie Lamport（Compaq → Microsoft Research）
**Read on**: 2026-05-14 (in lessons 5.2, 5.3)
**Status**: PDF 開放 https://lamport.azurewebsites.net/pubs/lamport-spec-tla-plus.pdf；已下載到 assets/papers/lamport-1999-tla-plus.pdf
**One-line**: TLA (Temporal Logic of Actions) 配 ZF set theory + first-order logic 形成 TLA+ 規格語言——concurrent / distributed system spec 不必用 pseudo-code, 直接用 math 寫。

## Problem
- 1980s-90s 多個 concurrent system spec 語言（CCS, CSP, Z, VDM）各有 trade-off
- 純 process algebra (CCS, CSP) 對某些 property 表達 awkward
- 純 logic (Z) 對 dynamic behavior 表達困難
- 需要一個語言: math-flavor, expressive for safety + liveness, support model checking

## Contribution
1. **TLA logic** (Lamport 1990, 1994): action 整合進 temporal logic
2. **TLA+ language** (1999): TLA + ZF set theory + first-order logic 完整 specification language
3. **Spec as single formula**: `Init /\ [][Next]_vars /\ Fairness`
4. **Stuttering**: spec allow vars unchanged steps — natural for concurrent system refinement
5. **Companion tools** later: TLC model checker (Yu-Manolios-Lamport 1999), Apalache (Konnov 2019), TLAPS proof system

## Method (just enough to reproduce mentally)
- **State** = valuation of variables
- **Behavior** = infinite sequence of states
- **Action** = relation between current state `v` and next state `v'`
- **Box `[A]_v`** = "A holds, OR all variables in v unchanged" (stuttering)
- **`[][Next]_v`** = always (Next action holds or stuttering)
- **WF / SF fairness** for liveness

## Results
- TLA+ 被 AWS (DynamoDB, S3, EBS), Microsoft Azure, Intel CPU spec, Mongo, etc. 大規模採用
- 多次發現 production system bug (Newcombe et al. CACM 2015)
- TLA+ Toolbox + VS Code extension active 維護
- TLA+ Conference annual community gathering

## Limitations / what they don't solve
- **不擅長 cryptographic protocol verification**: 沒 Dolev-Yao, 沒 unification
- **State space explosion** for large model checking
- **Refinement to executable code** 仍 manual / requires F\* / Stateright integration

## How it informs our protocol design
- **TLA+ 是 transport state machine 主工具**: 我們協議 packet number space, flow control, migration invariants 全用 TLA+
- **Spec-as-formula 是 spec-first methodology 的數學基礎**
- **Refinement lattice** 提供 high-level / low-level spec 結合的形式化

## Open questions
- TLA+ + adversarial process: 仍 manual idiom
- TLA+ refinement to verified Go/Rust code: PlusCal-to-code prototype but not production
- Probabilistic TLA+: 未在 mainline

## References worth following
- Lamport 1994 *The Temporal Logic of Actions* (ACM TOPLAS) — logic foundation
- Lamport 1977 *Proving the Correctness of Multiprocess Programs* (IEEE TSE) — safety vs liveness
- *Specifying Systems* (Lamport book 2002, free PDF)
- Wayne *Practical TLA+* (Apress 2018)
- Newcombe et al. CACM 2015

---

**用於課程**：Part 5.2 (TLA+ 入門)、Part 5.3 (TLA+ 進階)、Part 11.10 (我們協議 transport invariants)
