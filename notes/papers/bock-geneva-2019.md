# Geneva: Evolving Censorship Evasion Strategies
**Venue / Year**: ACM CCS 2019（CCS '19，London，November 2019），DOI 10.1145/3319535.3363189
**Authors**: Kevin Bock、George Hughey、Xiao Qiang、Dave Levin（University of Maryland，Breakerspace lab）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx adversarial co-evolution）
**Status**: full abstract + technical details via geneva.cs.umd.edu + kevinbock.phd + Semantic Scholar；PDF 二進位下載成功但 inline 解析失敗
**One-line**: 把「對 GFW / 印度 / 哈薩克的 DPI 規避」變成 genetic algorithm 問題——只用 drop / tamper / duplicate / fragment 四個 packet 原語演化出 30+ 個新策略（含 83% 重發現先前手工策略），完全自動、client-only、不需 server 配合。

## Problem
Censorship evasion 是 cat-and-mouse：每出新 censor 規則，研究員手工發現 bug、發 paper、censor 修補、又找新 bug。這個循環中**人**是瓶頸。問題：能不能讓「找新 evasion」這件事自動化？讓 genetic algorithm 自己 evolve 出規避策略，且策略要 (a) 純 client-only（不能改 server）、(b) 對 application transparent、(c) 對真實 censor（GFW、印度 DPI、哈薩克 MITM）有效？

## Contribution
- 提出 **Geneva**：第一個全自動 client-side censorship evasion engine。基因組由四個原語的樹狀組合構成。
- **四個 packet-level 原語**：
  1. **drop** — 丟棄 packet
  2. **tamper** — 修改 header / payload 任一欄位
  3. **duplicate** — 複製一份 packet
  4. **fragment** — 把 packet 切片
- **Fitness via live censor**：fitness function 是「跑這個策略對真 censor 的連線是否能完成」——不用任何 censor model，直接用真實環境當 oracle。
- 6000 行 Python，client-side 透過 Linux NetfilterQueue 攔截所有 in/out packet，按演化出的策略改寫。瀏覽器無需修改。
- 在 GFW、印度、伊朗、哈薩克四個真實 censor 環境跑出有效策略；其中 30/36 個先前 paper 手工發現的策略被自動重發現，並產生新策略（如 GFW 的 TCB-desync 變體）。

## Method (just enough to reproduce mentally)
1. 策略 = packet manipulation tree，nodes 是 trigger（哪個 packet 觸發）+ action（drop / tamper / dup / frag）。
2. Population: 隨機初始化 N 個策略樹。
3. Fitness: 每個策略對 censor 跑兩次 HTTP GET（含 censored keyword）；連線成功 = 高 fitness，被 RST / 注入 = 大負 fitness。取兩次最小值避免 false positive。
4. Selection: 取 top-k 進入下一代。
5. Mutation: 隨機改 node action / 加 subtree / 改參數值。Crossover: 兩個 tree 互換 subtree。
6. 終止: fitness 達 plateau 或 generation 上限。
7. Deployment: 把 winning strategy 用 NetfilterQueue 注入到實際 kernel netfilter chain，所有對應 packet 走改寫。

## Results
- 在 GFW HTTP 過濾上：演化出多個策略，包括 (a) 把 GET 切到「forbidden keyword」前後兩個 segment 不同 IP TTL、(b) 在 SYN 後送 RST 讓 GFW TCB 跑掉、(c) 在 HTTP request 前送 dummy bytes 讓 DPI parser 跳過——都能讓含 keyword 的請求穿過。
- 重發現 30/36 個先前手工策略（83.3%）。沒重發現的 6 個是 HTTP-layer 策略（Geneva 只在 packet 層）或長時間 pause 類（基因組沒這個原語）。
- 在 China / India / Kazakhstan / Iran 都有效部署。
- 持續演化能力——當 censor 修補某個策略，Geneva 重跑就找到新的。

## Limitations / what they don't solve
- **不抵抗 active probing**：GFW 主動探測 server 端 protocol fingerprint 不在 Geneva 攻擊面內。
- 純 client-only ⇒ 只能規避 DPI / 連線建立階段censor，無法處理 IP block。
- 策略對「censor implementation 細節」高度依賴；censor 換實作（如從 Suricata 換 Snort）策略全部失效，必須重 evolve。
- 不提供匿名性、不加密——它**只是讓被禁的連線能建立**。

## How it informs our protocol design
Geneva 帶給 protoxx 兩個方向的訊號：

**對手側**：未來會出現「自動演化的對手」——Geneva 的方法論對 censor 也成立，可以 evolve 出針對 protoxx 的 detection ruleset。protoxx 的 evaluation harness 應包含 Geneva-style adversarial co-evolution loop：把 protoxx 流量 + censor model（規則生成器）放進 GA，看多少代後 censor 能達到高 detection rate。

**防禦側**：Geneva 的 packet-level 原語（drop/tamper/dup/frag）也可以**反向**用——當 protoxx 偵測到鏈路上有 GFW-class probe 時，client 端主動用 Geneva 風格的 evasion 包裹流量，做 transport-layer 的 last-mile 防線。這條 fallback 路徑在 12.X 「實戰部署」是 nice-to-have。

## Open questions
- Geneva 風格 GA 能否 evolve 出 application-layer（HTTP/2 frame ordering、TLS extension 變形）的策略？目前只在 IP/TCP 層。
- 對 stateful、ML-based DPI（不是 rule-based），fitness gradient 是否還夠平滑讓 GA 能上山？

## References worth following
- Bock, Naval, Reese, Levin. *Geneva: Evolving Censorship Evasion Strategies for QUIC and Beyond.* FOCI 2020 / 後續 — Geneva 系列擴展。
- Wang, Wang, Yu, Zhang, Zhao, Krishnamurthy, Houmansadr. *Your state is not mine: A closer look at evading stateful internet censorship.* IMC 2017 — TCB desync 系列。
- Khattak, Javed, Anderson, Paxson. *Towards illuminating a censorship monitor's model to facilitate evasion.* FOCI 2013 — early manual TCB-desync 工作。

Source: [Paper PDF](https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf), [Project](https://geneva.cs.umd.edu/), [ACM DL](https://dl.acm.org/doi/10.1145/3319535.3363189)
