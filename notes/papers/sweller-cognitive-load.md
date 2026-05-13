# Cognitive Load During Problem Solving: Effects on Learning

**Venue / Year**: Cognitive Science 12(2), 257–285, 1988. DOI: 10.1207/s15516709cog1202_4
**Authors**: John Sweller (University of New South Wales, Australia)
**Read on**: 2026-05-14 (in lesson 0.2)
**Status**: full PDF (29 pages) at `assets/papers/cogsci-1988-sweller-cognitive-load.pdf` (read pp. 1–15 in detail; pp. 16–29 cover production system implementation details + computational model results + discussion)
**One-line**: Cognitive Load Theory 的奠基論文——證明 means-ends analysis（傳統 problem solving）跟 schema acquisition（learning）**爭奪同一個有限的 working memory**，所以「靠多解題學會」是錯的；**goal-free / worked-example** 才能釋放 cognitive capacity 給 learning。

## Problem

學界與教育界長期假設 **practice on conventional problems = best way to learn**——所以教科書編成「概念 → 大量類題」。但 Sweller 80 年代初的實驗發現：學生**能解題卻學不到 schema**——把練習題稍微變形就完全失敗。這違反所有教育假設。

問題：**為什麼解題練習無效？** 又：**有沒有更有效的 problem-solving practice 形式？**

## Contribution

1. **Schema 框架**：把 expert vs novice 差別 grounded 在**領域特定 schema** 而非一般 problem-solving heuristic。Expert chess master 不是「想得遠」而是 chunk 模式辨識（5–9 有意義棋型 vs novice 看到 random pieces）
2. **Means-Ends Analysis 的 cognitive load 證明**：用 production system 模型計算——MEA 需要的 working memory items 多到「**沒空間給 schema acquisition**」（5 個 means-ends production rules + 多個 subgoal stack vs goal-free 只 1 個 production rule）
3. **Goal-free（nonspecific goal）problem 的學習優勢**：把 "find acceleration of car" 改成 "calculate as many unknowns as possible"，**減少 cognitive load 同時加速 schema acquisition**——多次實驗證實
4. **奠基 Cognitive Load Theory**：之後 30 年教育研究的核心框架（germane / extraneous / intrinsic load 三分類在 Sweller 後續論文發展，本篇是源頭）
5. **解題 ≠ 學習** 的明確 separation——對教育設計有災難級的 implication

## Method

### Theoretical
- 對 expert-novice 文獻（chess、physics、algebra、computer programs）做 schema-theoretic synthesis
- 用 PRISM production system 建模 MEA vs goal-free 的 working memory load 差異

### Empirical（Sweller 與合作者既有實驗綜整）
- **Maze problems** (Sweller & Levine 1982): goal-known vs goal-unknown, 後者學到 structural feature 前者沒學到
- **Geometry/Trigonometry problems** (Sweller, Mawer & Ward 1983): goal-free condition 比 conventional 學更快
- **Algebra & physics**: 同一 pattern 重複

### Production System
- 4 個 means-ends productions vs 1 個 goal-free production
- 顯示 MEA 不只「**比較複雜**」而是 working memory 占用**質的區別**

## Results

- Goal-free condition 學生 **transfer test 表現顯著高**於 conventional condition（具體 effect size 散在多篇 Sweller earlier paper，本篇做 synthesis）
- Production system 模型量化：**MEA 需 ~5 productions + subgoal stack 同時 active**，而 goal-free 僅需 1 production
- **Maze experiment 直接證據**：goal-known novice 平均 fail to learn maze structure；goal-unknown novice 學到（顯著差異）

## Limitations / what they don't solve

- **Schema 定義模糊** — Sweller 定義為「allows recognition of problem state as belonging to category」，但 schema 的 fine structure 怎麼建模沒答
- **不適用所有領域** — Mathematics/physics/programming（清楚 problem space + 少 operators）效果好；對 ill-structured problems（design, writing, social）的應用未測
- **Computational model 是 idealised** — PRISM production rules 是 minimal idealisation，真實人類 problem solving 有並行 + heuristic shortcut，本模型沒包
- **沒處理 motivation** — Goal-free problem 可能讓 learner 失去 sense of progress；長期 motivation 影響沒分析
- **後續 expansion needed**：Worked example effect、split-attention effect、redundancy effect、modality effect 等都是 Sweller 後續論文補上的，本篇是 baseline

## How it informs our protocol design

**對 Phase III 程式實作階段 + 對我們協議 spec 寫作有直接影響**：

### 1. Spec 撰寫的 cognitive load 設計

Spec 文件是給未來實作者的 cognitive load source。用 Sweller 框架：

- **Intrinsic load**（協議本身複雜度）：難避免——加密 + 偽裝 + 連線管理本就複雜
- **Extraneous load**（spec 寫作引入的多餘負擔）：**這是我們可以優化**的——好的 spec 結構（清楚 state machine、明確 frame layout、separated concerns）降低 extraneous load
- **Germane load**（讀者建立 schema 的 effort）：用 RFC 8446 風格的章節對應 schema natural boundary

Phase III 11.5–11.8 寫 spec 時 explicit checklist：
- 每個 section 是否有單一 cognitive 主題（intrinsic load 不外溢）
- 每個 example 是否真的 worked example（不是讓 reader 自己 trace）
- 每個 forward reference 是否真的避免了，還是只是 push 給 reader（extraneous load）

### 2. 程式實作 vs schema 建立的張力

Phase III 12.x 寫 Go/Rust 實作 → 做 Sweller 警告的事情：寫一堆問題（debug + 跑 test）但學不到 schema。

對策：
- **Worked example first**：寫實作前看 wireguard-go 對應段落 + 註解過的 RFC，先 internalize schema
- **Goal-free exploration**：不是「實作 SS-AEAD encrypt」，是「explore Go's crypto/cipher package 看哪些 primitives 可組合」
- **避免 means-ends 困局**：不要在沒有 schema 的情況下 "make this test pass"——那是 cognitive load 黑洞

### 3. 對使用者學習本門課的隱性建議

- **看別人實作（Xray、sing-box、wireguard-go 通讀）= 大量 worked example**
- **每個 lesson 結尾的 self-check** 是 retrieval practice，但**第一次**問題該開放：「你能想到幾個用途/變形」（goal-free），第二次才收緊到「這個算法的時間複雜度」（conventional）
- **避免**「Read Chapter 1, do 30 exercises」式的學習（masses on type, schema acquisition 失敗）

### 4. 對 evergreen notes 系統的啟示

Andy Matuschak 的「concept-oriented」對應 Sweller 的 schema-oriented：
- **每一張 evergreen note = 一個 schema**
- 寫成 atomic（不混 schema）+ phrased as claim（schema 的 invariant）= 直接對應 Sweller 的 expert-cognition
- 我們 `notes/concepts/` 將來建立時，每張卡片要過 "is this one schema or many?" 的 sanity check

## Open questions

- **AI assistance（Claude）對 cognitive load 的影響**：當 working memory 有 Claude 當外腦時，Sweller 的 4-item limit 還相關嗎？或是 cognitive load 重新分配到「對 AI output 的 verification」？
- **Programming 領域的 worked example effect** 多強？跟 mathematics 比？很多軟體工程教學還在「寫多就會」階段，少 schema-grounded design
- **Means-ends 在新型 problem 也不利**？我們協議設計是 ill-structured problem——不知 schema 長什麼樣，是否仍該 goal-free？或在 ill-structured domain 反而 means-ends 是合理 starting point？
- **Cognitive Load Theory 對 LLM training** 是否有對應？LLM 看 worked example 學得好還是 goal-directed 學得好？這是最近 ML 教育學的開放問題

## References worth following

- **Chase & Simon (1973)** *Perception in chess* — schema in chess masters 經典
- **Larkin, McDermott, Simon, & Simon (1980)** *Expert and novice performance in physics* — physics expert-novice schema
- **Sweller, Mawer & Ward (1983)** *Development of expertise in mathematical problem solving* — goal-free 在 algebra/physics 的具體實驗
- **Sweller & Levine (1982)** *Effects of goal specificity on means-ends analysis and learning* — maze experiments
- **Egan & Schwartz (1979)** *Chunking in recall of symbolic drawings* — electronic circuits expert recall
- **Sweller subsequent**: Cognitive Load Theory book (2011)——本論文的 30 年總結

## 跨札記連結

- **與 Cepeda 2006**：Cepeda 量化 spacing「**何時**重訪」的最佳劑量；Sweller 量化「重訪時**呈現方式**」的設計（worked example > naked problem）。兩者組合起來才是完整的 instructional design
- **與 Rohrer & Taylor 2007**：Rohrer-Taylor 證明 mixed practice > blocked practice **在 procedural domain**——這跟 Sweller 的 schema discrimination training 一致（mixed 練習迫使 learner 學 *which* procedure 而非 *how*）
- **與 Schwartz 2008**：Schwartz 的「stupid」感覺 = Sweller 的 high cognitive load 體驗。Productive stupidity = 學習在 happen，但要避免 extraneous load
- **與 Hamming 1986**：Hamming 「working with the door open」= 暴露在 environment schema 訊號（learn schema implicit）vs door closed = 純 means-ends（短期效率，長期 schema 落後）
- **與 Andy Matuschak evergreen notes**：concept-oriented atomic note = schema instance；本論文 = evergreen note 系統的學理依據
- **直接 inform** Phase III 11.5–11.8 spec 寫作 + 12.x implementation 階段的 cognitive load 自我檢查
