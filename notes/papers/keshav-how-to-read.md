# How to Read a Paper

**Venue / Year**: ACM SIGCOMM Computer Communication Review (CCR), Vol. 37, No. 3, July 2007
**Authors**: S. Keshav (David R. Cheriton School of Computer Science, University of Waterloo)
**Read on**: 2026-05-14 (in lesson 0.3)
**Status**: full PDF (3 pages) at `assets/papers/sigcomm-ccr-2007-keshav.pdf`
**One-line**: 把讀論文這個從來沒人教的技能，拆成一個三遍漸進式 protocol，每一遍有明確目標、產出、停損條件。

## Problem

研究員每年花數百小時讀論文，但「**怎麼讀論文**」這件事學界從來不教。新手研究生 trial-and-error，浪費大量時間在錯的論文上、或在對的論文裡迷路。

## Contribution

提出 **three-pass approach**：把讀一篇論文拆成三個漸進式的 pass，每個 pass 有明確目標、時間預算、輸出，並可在任何一遍後停止。同時把這個方法擴展到 **literature survey**（陌生領域的文獻盤點）。

## Method

### First pass（5–10 分鐘）— bird's-eye view
讀 title、abstract、intro、所有 section/subsection 標題、conclusion、references（看哪些已讀）。產出 **Five Cs**：
1. **Category**：measurement / system / theory / SoK / position
2. **Context**：跟哪些論文對話、用了什麼理論基礎
3. **Correctness**：假設看起來合理嗎
4. **Contributions**：宣稱的貢獻是什麼
5. **Clarity**：寫得清楚嗎

第一遍後可選擇放棄（不感興趣 / 背景不夠 / 假設無效）。**多數論文應該停在這裡。**

### Second pass（最多 1 hour）— 內容掌握
仔細讀，但跳過證明。重點看 figures（軸標、log scale、誤差棒——「常見錯誤把 rushed shoddy work 從 truly excellent 區分開」），標出值得追的 references。
出口能力：能對非該領域同行口述論文主旨 + 主要證據。
卡住的處理：(a) 放棄、(b) 補背景後回來、(c) 進第三遍。

### Third pass（新手 4-5 hr，老手 1 hr）— virtual re-implementation
**核心動作：用作者同樣的假設，自己重新發明一次方法，再對比作者怎麼做的。** 出入處就是學設計取捨的地方。
出口能力：閉著眼睛重建論文結構，能說出隱含假設、缺漏引用、實驗或分析手法的潛在問題。

### 用三遍法做 literature survey
1. 用 Google Scholar / CiteSeer 加 keywords 找 3-5 篇 recent paper，每篇做一遍 + 讀其 related work
2. 從 bibliography 找**重複出現的引用與作者**——這些是該領域 key papers / researchers
3. 去 key researchers 的網頁找他們最近發表在哪 → 識別 top conferences
4. 去 top conferences 的 recent proceedings 掃一遍 → 補完高品質近期論文
5. 對所有候選論文做兩遍（first + second），如有共同未讀引用就追加

## Results

沒有實驗——這是 method paper / position paper。作者自陳 15 年實踐有效。

## Limitations / what they don't solve

- **沒給「停損條件」量化標準**：第二遍跟第三遍之間的決策（「值得做第三遍嗎？」）完全靠 judgment
- **隱含假設論文寫得好**：對於 poorly-written paper（「unsubstantiated assertions and numerous forward references」）方法效率會崩，作者只給了「放棄 / 補背景」兩個出路
- **沒講怎麼**處理 long-form 文獻（書、blog post、技術報告）。三遍法為 conference paper 量身打造
- **沒講協作 / 對話形式的閱讀**（reading group、journal club）——這在現代研究實踐中越來越重要
- **2007 寫的，沒覆蓋當代工具**：Semantic Scholar、Connected Papers、AI 論文摘要工具都改變了 literature survey 的成本結構

## How it informs our protocol design

對我們研究的直接影響：

1. **Phase II 我們會碰 ~50 篇論文**，全部走「first → second → 多數停 → 少數第三遍」這個 funnel。沒這個 funnel 我們會在 Part 9 GFW 文獻 25 篇處死掉。
2. **Part 11 設計階段**做新文獻 survey 時，第三節「擴展到 literature survey」的五步法直接用——特別是「找重複作者 → 找他們最近發在哪 → 識別 top conferences」這條路徑。
3. **Phase III 12.22 寫論文 intro/related work** 時，相當於在做反向工程：寫一篇能讓未來讀者用三遍法快速判讀我們論文的 paper。Section/subsection title 的 coherence、abstract 的 conciseness 是 reviewer 給或拒的關鍵——作者明白點出「first pass 看不懂就 reject」。
4. **Five Cs 直接內化成本門課論文札記模板**的早期欄位（One-line 對應 Contributions + Clarity）。

## Open questions

- AI 摘要（Claude / GPT / Semantic Scholar TLDR）是否該在 first pass 之前加一步「AI pass（< 1 min）」？這會 contaminate 我自己對論文的判讀嗎？
- 對於**超長 paper / book chapter**（如 Tanenbaum 那種教科書章節），三遍法該怎麼擴展？
- 三遍法假設**每篇獨立讀**，但實務上常常一個 session 讀 3-5 篇相關論文。**batched reading** 該不該有自己的 protocol？
- 作者自己 15 年實踐——但他是 networking 教授。對其他子領域（密碼學、形式化方法、ML）的論文，三遍法的時間預算與停損點該怎麼校準？

## References worth following

論文的 §5 Related Work 給了 4 篇姊妹文，全是研究技能類：

1. **S. Peyton Jones**, *Research Skills*（網頁，covers entire spectrum） — Haskell 共同設計者，Microsoft Research，演講稿全集 ⭐
2. **T. Roscoe**, *Writing Reviews for Systems Conferences* — 寫 review 的對應指南
3. **H. Schulzrinne**, *Writing Technical Articles* — RTP 設計者，CS 寫作風格指南
4. **G. M. Whitesides**, *Whitesides' Group: Writing a Paper* — 化學界傳奇 PI 的論文寫作 SOP，跨學科借鑒

Adler 1940 *How to Read a Book*（Keshav 沒引但是源頭）是這個方法論的祖先——Adler 提出四層閱讀法（elementary / inspectional / analytical / syntopical），Keshav 的三遍法可以視為其「inspectional → analytical」段落的 CS 論文版簡化。
