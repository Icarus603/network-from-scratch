# QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs
**Venue / Year**: ICFP 2000（International Conference on Functional Programming，Montréal），ACM SIGPLAN Notices 35(9), pp. 268–279
**Authors**: Koen Claessen、John Hughes（Chalmers University of Technology）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx property-based test 的奠基論文）
**Status**: full PDF accessible via cs.tufts.edu mirror
**One-line**: 提出 **property-based testing**：開發者寫程式「應該滿足的性質」（如 `reverse (reverse xs) == xs`），QuickCheck 自動生成隨機輸入並驗證；找到反例後再 shrink 到最小——把 testing 從「寫死的 input/output pair」變成「執行 specification」。

## Problem
傳統 unit testing 是 example-based：手寫一組 (input, expected output) pair。問題是 (a) cover rate 取決於開發者想得到的 corner case；(b) 對泛型 / 抽象資料結構，想出 input 需要工程力氣；(c) 沒有 specification 與 test 的對齊機制。Hughes 等 Haskell 社群想要：能不能讓「test = property = small spec」？

## Contribution
- 提出 **property-based testing** 範式：test = `forall x. P(x)` 形式的可執行 predicate。
- 設計 **monadic random generator** type class `Arbitrary`：每個 type 提供 `arbitrary :: Gen a` 與 `shrink :: a → [a]`，組合性極強——`Gen (Tree Int)` 從 `Gen Int` 與 generator combinator 自動推導。
- **Shrinking**：當 property 失敗，自動 minimise 反例：對 list shrink 拆成短 list、對 int shrink 往 0 靠。讓 debug 時看到的反例是最小可重現的形式。
- 在 Haskell 程式（list sort、binary tree invariants、Edison 容器庫）上展示找 bug 能力。
- 開源 QuickCheck library，後續被 port 到 Erlang（Quviq）、Scala（ScalaCheck）、Python（Hypothesis）、Rust（proptest, quickcheck-rs）、Go（gopter）、Java（jqwik）。

## Method (just enough to reproduce mentally)
1. 開發者寫 property：`prop_reverse :: [Int] → Bool ; prop_reverse xs = reverse (reverse xs) == xs`。
2. QuickCheck：對 N 個（預設 100）random `xs` 用 `arbitrary` generator 生出，evaluate property。
3. 若任一回 false，停下；用 `shrink :: [Int] → [[Int]]` 列出更小的候選，找最小仍然 false 的版本。
4. 報告：「Property failed at xs = [1,−1]」（minimal counterexample）。

關鍵抽象：
- `Gen a` 是 reader monad over random seed + size parameter；組合 `liftM2 (,) genA genB` 直接得 `Gen (a, b)`。
- Size parameter 控制 generator 規模——小 size 先測 simple case，逐步加大；對 recursive type（樹）避免無限遞迴。
- `Arbitrary` instance 對 user-defined type 寫一次後永久可用。

## Results
- 在 Edison library 找出多個之前未發現的 invariant 違反。
- 對 GHC 標準 library 的 sort 找出邊界 bug。
- 證明 property-based testing 對泛型容器特別有效——因為 property 自然是 polymorphic。
- 開啟了 20 年 PBT 工具發展，至今仍是業界 SOTA testing 範式之一。

## Limitations / what they don't solve
- random generator 對深 spec（如「symbol table 在 N 次操作後仍滿足 invariant X」）需要寫 state machine generator，門檻較高。
- 純 random 對「需要精確 magic value」的 bug（如 hash collision 觸發的 corner case）效率差——後續 coverage-guided fuzzing（AFL）才補上。
- 沒有 shrink 時，反例往往幾百個元素長，debug 困難——後續工具如 Hypothesis 把 shrinking 做成一等公民。

## How it informs our protocol design
protoxx 的 wire format / state machine / KDF chain 全是 property-based testing 的天然戰場。具體：
1. **Wire format**：`prop_roundtrip f = decode (encode f) == f` 對每個 Frame variant 都該成立——這條 property 一寫就免費 cover 所有 padding / length / framing edge case。
2. **State machine**：`prop_no_invalid_transition trace = all (\step → validTransition (prevState step) (action step) (currState step)) trace`。
3. **AEAD record layer**：`prop_decrypt_after_encrypt key nonce ad pt = decrypt key nonce ad (encrypt key nonce ad pt) == Just pt`。
4. Rust 端我們用 **proptest** crate（QuickCheck 後裔）；CI 必跑。
5. 對 handshake state machine 進一步用 **stateful model-based testing**（state machine generator + Lin/Ari 風格 trace）——這是 12.X 的標配。

## Open questions
- 對 protocol fuzz，property-based + coverage-guided（AFL-style）混合是否更有效？proptest + arbitrary corpus seed 是當前 Rust 社群的方向。
- 怎麼把 property 的「expected」與形式驗證（ProVerif / Tamarin）的 specification 自動對齊？

## References worth following
- Hughes. *QuickCheck Testing for Fun and Profit.* PADL 2007 — Erlang QuickCheck 與 commercial 用例。
- Hughes. *Experiences with QuickCheck: Testing the Hard Stuff and Staying Sane.* Festschrift 2016 — 真實工業使用回顧。
- MacIver, *Hypothesis* (Python) — 把 shrinking 提升為 first-class search problem。

Source: [Paper PDF (Tufts mirror)](https://www.cs.tufts.edu/~nr/cs257/archive/john-hughes/quick.pdf), [QuickCheck on Hackage](https://hackage.haskell.org/package/QuickCheck)
