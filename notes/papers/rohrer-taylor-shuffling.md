# The Shuffling of Mathematics Problems Improves Learning

**Venue / Year**: Instructional Science 35(6), 481–498, November 2007. DOI: 10.1007/s11251-007-9015-8
**Authors**: Doug Rohrer, Kelli Taylor (Department of Psychology, University of South Florida)
**Read on**: 2026-05-14 (in lesson 0.3)
**Status**: full PDF (18 pages) at `assets/papers/instr-sci-2007-rohrer-taylor-shuffling.pdf`
**One-line**: 兩個實驗證明數學練習中**spacing**（分散練習）和 **interleaving**（混合題型）兩個調整都大幅提升 1 週後測驗成績——前者 +25 個百分點，後者 +43 個百分點。

## Problem

絕大多數數學教科書的練習是 **massed + blocked**：
- **Massed**：剛教完的概念馬上做 12 題類似的，不再回顧
- **Blocked**：每組練習單一題型，不混入其他題型

這個格式跟認知心理學已知的 **spacing effect**（spaced practice 比 massed 好）和 **interleaving** 假設衝突，但**數學領域沒被嚴格實驗驗證過**——本論文補上。

## Contribution

1. **第一個對「數學 overlearning」做嚴格 null result 實驗**——Light Massers（2 題）vs Massers（4 題）vs Spacers（2+2 題隔週）：multiplied study time **沒提升** 1 週後測驗（前兩組 49% vs 46%，no significant difference）
2. **重複驗證 spacing effect 在數學領域的存在**——Spacers 74% > Massers 49%（+25 percentage points）
3. **首次直接比較 mixed vs blocked 數學練習**——Mixers 63% > Blockers 20%（+43 percentage points），雖然 Blockers 練習階段表現更好（89% > 60%）
4. **發現 desirable difficulty**：練習階段表現好的策略（blocked, massed）跟長期記憶 negatively correlated

## Method

### Experiment 1（spacing + overlearning, n=66 大學生）
- Task：算字串 abbccc 的不重複排列數（permutations with repetition）
- 三組：
  - **Spacers**：第 1 週做 2 題 + 第 2 週做 2 題 + 第 3 週測
  - **Massers**：第 1 週做 4 題 + 第 2 週測
  - **Light Massers**：第 1 週做 2 題 + 第 2 週測
- 三組都在第 3 週做 5 題的 final test
- 訓練了 base rate：50 個沒參與的 control 全沒答對（task 對 participant pool 完全 novel）

### Experiment 2（interleaving, n=18 大學生）
- Task：算 4 種幾何體（wedge / spheroid / spherical cone / half cone）的體積
- 兩組：
  - **Mixers**：4 種題型隨機混合
  - **Blockers**：1 種題型一組（4 題），4 組共 16 題
- 兩組總題數、tutorial、interval 全一樣，**只**差 problem order
- 第 1, 2 週各做 16 題練習，第 3 週測

### Test
- 1 週後 8 題（每種 2 題），無 feedback，8 分鐘

## Results

### Experiment 1
- **Spacers 74%** > Massers 49% > Light Massers 46%（最後兩組 not significantly different）
- F(2, 57) = 3.59, p < 0.05, η²p = 0.11
- **Overlearning 沒效果**——Massers 跟 Light Massers 沒差，但 Massers 用了 2x time
- 與 Rohrer & Taylor 2006 的 null result 一致

### Experiment 2
- **Mixers test 63%** vs **Blockers test 20%**（t(14) = 2.64, p < 0.05, d = 1.34）
- **Practice 反過來**：Blockers practice 89% > Mixers practice 60%（t(16) = 3.14, p < 0.01）
- **F(1, 16) = 35.08, p < 0.001** for the practice-strategy × phase interaction
- 99% test 錯誤是用錯公式——表示 Blockers 學會了 *how* but not *which* procedure 適用哪題型

## Limitations / what they don't solve

- **n 小**：Exp 1 n=66, Exp 2 n=18——後者 power 不足以排除 ceiling/floor effects（雖然 effect size 巨大）
- **lab setting**：未驗證教室實際使用的 ecological validity
- **task 程序性 > 概念性**：兩個 task 都是「套公式」型，沒測 deeper conceptual learning
- **transfer 沒測**：只測題型完全相同 transfer，沒測 near transfer 或 far transfer
- **無年齡多樣性**：全大學生，K-12 兒童效果未知
- **interaction with 內容難度** 沒探討
- **長期 retention beyond 1 week** 沒測

## How it informs our protocol design

**間接但極關鍵——直接支持 lesson 0.2 策略 C（混合動力版）的選擇**：

1. **Spacing effect** → 0.2 策略 C 推薦「**Phase 內並行多線**」就是 spacing：每週各推進不同 Part 1~2 堂，讓每個 topic 自然分散
2. **Interleaving > blocking** → 跟策略 B（線性版「一次一個 Part」= blocking）的批評對齊。實驗證據是大學生 +43 percentage points
3. **Desirable difficulties (Bjork)** → 0.2 §3 「卡住三類型」的哲學基礎：學習階段感覺 difficult ≠ 學習效果差。Mixers 在 practice phase 比 Blockers 慘，但 test 上贏 3x
4. **Anti-overlearning** → 對應 0.2 §3 type 1 (詞彙缺) 的處理：查 glossary 一次就好，不要重複「掌握」
5. **「Practice performance ≠ test performance」**: 對 Phase III 評測有元層級意義——我們協議在 lab benchmark 漂亮不代表 deployment 漂亮（與 Tschantz 的 evaluation realism 主題呼應）

**對 Phase II/III 學習 schedule 的具體建議**：
- **不要連讀完 Part 9 才碰 Part 10**——交錯讀，保留 spacing
- **Part 6/7/8 三個翻牆協議家族 interleave 讀**，不要 block
- **論文閱讀 schedule**：每週讀 3 篇不同主題，比集中一週讀 3 篇同主題長期保留好
- **Self-check 自我檢查問題**：spacing 重做更有效——跨 lesson 回頭做之前的 self-check

## Open questions

- 對於**研究級**內容（不只是套公式），interleaving 效果是否仍 +43 percentage points？沒研究
- 12 卷課程的最佳 interleaving granularity 是什麼？小時級？日級？週級？
- AI advisor 的存在是否改變 spacing/interleaving 的最佳劑量？——當你卡住可以隨時問 AI 解決，是否減弱了 desirable difficulty 的訓練效果？
- "**Mixed practice 對 procedural learning 有效**" — 但對 spec 設計、formal verification 這種**概念性**任務的效果如何？

## References worth following

論文 §References 的關鍵脈絡：

- **Bjork, R. A. (1994)** — *Memory and metamemory considerations in the training of human beings* — Bjork 的 desirable difficulties 概念源頭
- **Cepeda et al. (2006)** *Distributed practice in verbal recall tasks: A review and quantitative synthesis*. Psychological Bulletin 132, 354–380 — spacing effect 的 meta-analysis 金本位
- **Schmidt & Bjork (1992)** *New conceptualizations of practice* — desirable difficulty 系列開山
- **Pashler, Rohrer, Cepeda, & Carpenter (2007)** *Enhancing learning and retarding forgetting* — 同作者群的延伸
- **Bahrick, Bahrick, Bahrick, & Bahrick (1993)** — long-term language retention 經典實驗

延伸（不是論文 cite 的，但同一脈絡）：
- **Karpicke & Roediger (2008)** *The critical importance of retrieval for learning* (Science)
- **Brown, Roediger, McDaniel** *Make It Stick* (2014) — 把上面這串研究科普化

## 跨札記連結

- **與 Keshav 2007**: Keshav 三遍法的 "stop after first/second pass" 對應 anti-overlearning——不是每篇都要深讀
- **與 Hamming 1986**: Hamming 的 "knowledge compounds" 機制裡，spacing 是 compound 速率的關鍵——同樣時間，spaced 的留存複利率更高
- **與 Schwartz 2008**: 練習中感覺 stupid（mixed practice）= Schwartz 的 productive stupidity 在學習層的具體實作
- **直接 inform** 了 0.2 §2 三種讀法策略的選擇（推薦 C，與本篇的 spacing+interleaving 證據一致）
- **直接 inform** 了 CLAUDE.md 的 lesson template length policy：每堂 30~60 分鐘 + 跨 part 並行——隱含 spaced + interleaved 設計
