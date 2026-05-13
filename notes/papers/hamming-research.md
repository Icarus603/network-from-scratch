# You and Your Research

**Venue / Year**: Bell Communications Research Colloquium, 7 March 1986. Transcribed by J. F. Kaiser.
**Authors**: Richard W. Hamming (Naval Postgraduate School + retired Bell Labs)
**Read on**: 2026-05-14 (in lesson 0.3)
**Status**: full transcript (16 pages) at `assets/papers/talk-1986-hamming-research.pdf`
**One-line**: 一個跟 Shannon、Feynman、Oppenheimer、Fermi 共過事的 Bell Labs 老兵，把「為什麼有些人能做 first-class work 而你不能」逐項拆解成可執行的工作習慣與心態。

## Problem

學界長期半信「great work = luck + genius」，於是研究員無從 deliberate practice。Hamming 用 40+ 年觀察 + 親身與多位 Nobel 等級科學家工作的經驗 argue：**great work has identifiable habits, and they are learnable**。

## Contribution（提取的具體工作原則，按重要性排序）

### 1. **Work on important problems**
- Bell Labs 同事多數人花全部時間在他們認為**不會通向重要結果**的問題上
- 「important problem」必須**phrased carefully**——時光旅行/隔空傳物/反重力不是 important，因為**沒有 attack**
- 重要 = 你有可信的 attack angle + 結果會 matter
- 行動：每週五午餐只談 great thoughts；列出領域 10–20 個 important problems 隨時待戰

### 2. **Knowledge & productivity compound like interest**
- 同樣能力的兩個人，多投入 10% 的人 long-run produces 2x+
- "Genius is 99% perspiration"（Edison）—— Hamming 強調是 **steady applied** 努力
- 重要的是 **applied sensibly**，不是「忙就好」

### 3. **Courage to attempt important problems**
- Shannon 的 noisy coding theorem：他大膽問「average random code 會怎樣」——這需要 courage
- "If you think you can't, almost surely you are not going to"

### 4. **Good working conditions = bad working conditions**
- "Best" working conditions（Cambridge 不是 shacks）often correlate with 最 productive periods
- 缺陷**強迫**創新（Hamming 被迫做 automatic programming）—— defects can become **assets**
- 反例：把 defect 當 fault 抱怨 = 缺乏 great worker mindset

### 5. **Tolerate ambiguity**
- Great scientists **simultaneously** believe a theory enough to use it AND doubt it enough to spot the holes
- 太相信 → 看不到 flaws；太懷疑 → 不能開始
- Darwin 強迫自己**寫下所有反證**，否則大腦會自動忘記

### 6. **Drop other things, pursue opportunities**
- Great scientists 看到 opportunity 立即 drop 其他事追上去——他們已經 prepared mind
- "**Luck favors the prepared mind**" (Pasteur)

### 7. **Open door (literally and metaphorically)**
- 關門做事**今天**比較 productive，**10 年後**你不知道什麼問題重要
- 開門 = 接受 interruption + 接收 environment signal

### 8. **Sell your work**
- Great work + bad presentation = 没人看
- 三件 selling skills：清楚的寫作、formal talk、informal talk
- 50% 時間投入 polish/presentation 是合理的

### 9. **Cooperate with the system, don't fight it**
- 與其挑戰 system，學習如何**用** system
- 想要 No 才開口問；想要 Yes 直接做完拿成果展示
- Ego assertion (堅持自己風格) makes you pay steady price for whole career
- John Tukey 的無形 cost / Barney Oliver 的 efficient style 對比

### 10. **Periodic reinvention** (every ~7 years)
- 用完一個領域的 originality 後要 shift
- Shannon 沒做 → "ruined himself" 後信息論之後沒大成就
- 7 年是 Hamming 的經驗值

### 11. **Convert defects into assets**
- 自我欺騙是 universal trap
- 不要 alibi——對外可以，對自己要 honest

### Q&A 重點
- 對 brainstorm：選 capable 對話對象，避開 "sound absorbers"（只說「對對對」的人）
- 對 management：第一-class research 是 in spite of management，不是 because of
- 對年齡：「shift fields every 7 years」並非降級，是必要更新

## Method

40+ 年第一手觀察 + 5 個直接共事的 first-class scientists（Shannon, Feynman, Bethe, Fermi, Teller, Oppenheimer）+ 系統性自我介入實驗（cooperate vs ego-assert）。Talk 後跟著 Q&A，許多細節在 Q&A 才出來。

## Results

無量化結果（不是研究論文）。但 Hamming 自己在 Bell Labs 確實 "highly productive against many others who were better equipped"——本身就是觀念的存在性證明。

## Limitations / what they don't solve

- **倖存者偏差**：Hamming 訪談的全是 succeeded scientists；沒看到「也有這些 habits 但失敗的人」的 base rate
- **時代局限**：1986 Bell Labs 環境特殊（無短期 deliverable 壓力 + 終身雇用 + 無 quarterly review）；現代學界 publish-or-perish 環境下 "open door" 等習慣的 cost-benefit 不同
- **領域局限**：以 mathematics/physics/EE 為主——對 biology / social science / humanities 不一定 transferable
- **個人化建議的副作用**：Hamming 自己承認 Tukey 的 ego assertion style 雖然付出 cost，但 Tukey 仍是 genius——也許某些「defects」是 talent 的不可分割部分
- **沒有失敗 protocol**：每個 advice 都是「成功者該做什麼」，少談「卡住該怎麼診斷」

## How it informs our protocol design

**Phase III 整體工作 attitude**的奠基讀物。具體 habit 移植：

1. **Important problem framing** (#1) → Part 11.1 威脅模型撰寫時，明確 declare 「what makes our problem important + what's our attack」
2. **Compound interest of work** (#2) → 本門課承諾 1.5–3 年的合理性——複利效應不是線性而是指數
3. **Courage to attempt** (#3) → "**比 VLESS+REALITY 抗審查 + 比 Hysteria2 速度** simultaneously" 這個目標需要 Hamming 式的 courage——別人會說 "trade-off impossible"
4. **Defects as assets** (#4, #11) → 第一次評測協議被打爆時，那個被打爆的 attack vector 就是設計的 asset，給我們**新角度**
5. **Tolerate ambiguity** (#5) → Part 11 設計時要同時相信 design rationale 和 doubt assumption——不是相反
6. **Drop and pursue** (#6) → 如果 Phase II 中讀到一篇論文 reveal 一個我們沒想過的設計方向，要 drop 當下 schedule 追上去
7. **Open door** (#7) → 為什麼這個 repo 是 public 的——signal acceptance + environment input
8. **Sell** (#8) → Part 12.22 寫論文是 50% 工作量，不是 add-on
9. **Cooperate with system** (#9) → 學界 publish 機制不喜歡也得學會 navigate（USENIX Security/NDSS deadline、reviewer style、camera-ready format 規範）
10. **7 年 shift** (#10) → 結業後不是繼續做 G7 G8 而是換領域，避免 Shannon 後遺症

## Open questions

- AI 時代的 "open door" 與 "ambiguity tolerance" 怎麼變？永遠有 Claude 在會降低 ambiguity tolerance 嗎？
- "**Knowledge compounds**" 在 information overload + 領域擴張的 2026 還成立嗎？或者 returns to scale 已經 diminishing？
- "Drop other things to pursue opportunity" vs "stay focused" 的判定 protocol——Hamming 沒給
- Hamming-style cooperation with system 在現代 toxic academic culture（grant 競爭、citation gaming）下還最優嗎？

## References worth following

Hamming 在 Q&A 提到的：
- **Tukey**'s casual dress — 與 ego assertion cost 案例
- **Barney Oliver**'s letter to IEEE — 規範 reform 的 minimal-effort style 案例
- **Schelkunoff** — "you set your deadlines, you can change them" 案例

延伸閱讀（不是 Hamming 引的）：
- **Hamming, *The Art of Doing Science and Engineering: Learning to Learn*** (1997) — 本 talk 的書本擴充版，30 年職業反思
- **Cal Newport, *Deep Work*** (2016) — Hamming work habits 的現代版
- **Peter Drucker, *Effective Executive*** (1966) — knowledge worker productivity 的姊妹經典

## 跨札記連結

- **與 Schwartz 2008**：Schwartz 的 productive stupidity = Hamming 的 "tolerate ambiguity"——同一現象的不同年代/領域命名
- **與 Keshav 2007**：Keshav 三遍法是 Hamming "knowledge compounds" 的具體 protocol
- **直接寫進** 0.3 §1 deliberate practice、0.3 §3 失敗管理、0.3 §5 我們協議的座標 — Hamming 的 #1, #3, #5, #6 全是 motivation
