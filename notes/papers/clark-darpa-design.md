# The Design Philosophy of the DARPA Internet Protocols

**Venue / Year**: ACM SIGCOMM Computer Communication Review 18(4), August 1988, pp. 106-114
**Authors**: David D. Clark (MIT Laboratory for Computer Science)
**Read on**: 2026-05-14 (in lesson 1.1)
**Status**: full PDF (29 pages, including SIGCOMM 95 reprint) at `assets/papers/sigcomm-1988-clark-darpa-design.pdf` (read TOC + intro + key sections)
**One-line**: Internet 設計師 Clark 的內部回顧——明確列出 DARPA Internet 的 **7 個設計目標、有優先順序**：survivability 第一、accountability 最末——這個順序解釋了今天 Internet 為何長這樣，以及為何 GFW 必須**在 architecture 之上**運作而非 within。

## Problem

1988 年 Clark 寫這篇時，TCP/IP 已經部署 15 年。但**沒有任何文獻清楚記錄**為什麼當初做出這些設計選擇。Clark 是少數一直在場的設計者之一，寫這篇就是要把當時的「設計哲學」記錄下來，避免後人誤解。

## Contribution

1. 明確列出 **7 個 DARPA Internet 的 fundamental goals**，**按優先順序**（這是論文最重要的貢獻）：

   | # | 目標 | 含義 |
   |---|---|---|
   | 1 | Survivability in face of failure | 部分節點/網路失效仍能通訊 |
   | 2 | Multiple types of service | 支援不同 application（檔案傳輸、即時通訊、虛擬電路） |
   | 3 | Variety of networks | 跨多種底層網路（衛星、無線、有線）|
   | 4 | Distributed management | 沒中央控管 |
   | 5 | Cost effective | 便宜 |
   | 6 | Host attachment with low effort | 接一台新 host 不該需要重大修改 |
   | 7 | Accountability of resources | 知道誰用了多少資源 |

2. **解釋每個目標如何驅動具體的 architecture decision**：
   - Survivability 第一 → **fate sharing**（state 放 endpoint，不放 router）
   - Multiple types of service → IP 層做最小公約數（best-effort datagram），上層自行加 reliability/ordering（TCP）或不加（UDP）
   - Variety of networks → **packet switching + minimum assumption**（不假設底層特性）
   - Distributed management → no global routing authority；BGP 才能 work
   - Accountability **最末** → Internet 從一開始就**沒有實名制 / 計費機制**

3. 明確指出**這個順序如果反過來會發生什麼**：
   - 如果 accountability 排第一 → ATM / X.25 風格的 connection-oriented + central provisioning network
   - 如果 cost 排第一 → 沒有冗餘 routing
   - 如果 distributed management 排第一 → 可能根本沒有 Internet 這個東西

4. **誠實列出 7 priorities 沒涵蓋的 modern issues**：
   - 安全性（在 Internet 設計時不是 priority）
   - 隱私
   - QoS guarantee（best-effort 是個選擇，不是 default 真理）

## Method

純 retrospective architectural paper——靠歷史回顧 + 設計師自白。**沒有 quantitative method**。

主要說服力來自：
- 作者親身參與設計，**第一手見證**
- 把每個 architecture decision 跟某個 priority 連起來，論證閉環
- 對比若優先順序反過來會怎樣（counterfactual reasoning）

## Results

無實驗結果。**論證的力量在「解釋力」**——讀完後 reader 對 Internet 各種怪設計（IP fragmentation、no central authority、connection state at endpoints）都能 trace 到某個 design priority。

## Limitations / what they don't solve

- **後見之明偏差**：Clark 1988 寫的是 Internet 已經 work 之後的回顧。他不可能完全還原 1973 年的決策過程
- **Survivability 沒形式化**：「partial failure」具體什麼程度？沒給定義
- **Accountability 排第七的代價沒充分討論**：DDoS、spam、abuse 是 Internet 從未根本解決的問題，都源自此選擇
- **Security 完全缺席**：Clark 自己後來在 1995/2000 papers 反覆談「security 應該排第幾」這個問題
- **沒處理 GFW / sovereignty 議題**：1988 沒有民族國家試圖控制 Internet 的成熟案例（GFW 是 1998+）
- **沒考慮 commercial / multi-stakeholder 治理**：1988 Internet 仍是 academic + military，沒有商業 ISP

## How it informs our protocol design

**對 G6 的核心影響在「為什麼 GFW 必須 in-path / 為什麼我們無法 architectural bypass」**：

### 1. **GFW 的存在是 Internet design 的副作用**
- Survivability 第一 → fate sharing → **state 放在 endpoint**
- 但 packet **必須穿過中間 router** → GFW 可以放在 router path 上做 inspection
- **這是 architectural fact，無法改變**——除非完全重設計 Internet（QUIC 沒做、IPv6 沒做、未來也不會做）

### 2. **G6 必須在 application layer 做對抗**
- Internet 沒給「prevent intermediate inspection」的 architectural primitive
- TLS / encryption 是 application-layer fix，是**事後加的**
- G6 也只能是 application-layer fix → 不能寄望 routing trick / IP-level magic

### 3. **Accountability 排第七 = 為什麼翻牆協議可能存在**
- 如果 Clark 把 accountability 排第一，Internet 會有強制實名 + payment-per-packet
- 那種 architecture 下，Tor / VPN / VLESS 都不會存在
- **G6 的「存在可能性」直接源自 Internet 的 7-priority 順序**——這值得在 Phase III 12.22 論文 intro 提

### 4. **多協議共存是 architectural feature**
- "Multiple types of service" → IP 之上可以是 TCP / UDP / SCTP / QUIC / 任何新協議
- G6 可以選任何 transport（UDP-based 走 QUIC、TCP-based 走 TLS、甚至 raw IP）
- Internet architecture 本身**不阻止**新 protocol 出現——這是設計留下的彈性

### 5. **Survivability 的對偶**：GFW 也利用這個
- Internet 抗 partial failure → GFW 不能完全切斷 internet（會傷自己）
- GFW 的策略是**在不切斷的前提下做 selective block**——這是它的弱點
- G6 的 anti-detection 應該針對 GFW「不能 false-positive 太高」的弱點設計

## Open questions

- **如果今天重新設計 Internet，priority 順序會是什麼**？最常被提的是「security 排第二」、「accountability 排第三」——但這會殺死 Tor/VPN/翻牆生態
- **Survivability 在 cloud + CDN 集中化的時代仍是 priority 嗎**？AWS / Cloudflare 集中度極高，partial failure 已經造成 global outage——Internet 已經不是 1988 設計師想的那樣
- **GFW-style sovereign Internet 算「failure」嗎**？Clark 7 priorities 假設「failure 是技術性的（網卡壞、線斷）」，沒考慮「政治性 failure」（國家切斷）
- **後 quantum、post-AI Internet 的 priorities**：如果重新設計，要不要把 ML-resistant routing 加進去？

## References worth following

論文本身的 reference 多是 1970s–80s 的 Internet 內部技術文件，現代 most relevant 的是：

- **Saltzer-Reed-Clark 1984** End-to-End Arguments — 已建檔，是 fate sharing 的 design principle 表述
- **Reed 1976 dissertation** — fate sharing 的理論源頭
- **RFC 1958** Architectural Principles of the Internet (1996) — Clark + IAB 把 7 priorities 寫成 IETF 正式 architectural statement
- **Clark 1995** Adding Service Discrimination to the Internet Architecture — Clark 自己後來反思 priorities，加了 differentiated service
- **Clark, Wroclawski, Sollins, Braden 2002** Tussle in Cyberspace: Defining Tomorrow's Internet — Clark 等人對 priorities 的「現代化」修訂，加進「policy/administrative tussle」

## 跨札記連結

- **與 Saltzer 1984**：Saltzer 的 e2e argument 是「設計指南」，Clark 1988 是「實際應用 e2e 設計出 Internet 的歷史記錄」
- **與 Crowcroft 1992**：Crowcroft 揭露 layering 在實作時的 bug，補完 Clark/Saltzer 的「設計理想 vs 工程現實」缺口
- **與 Tschantz 2016 SoK** + **Wu 2023 FEP**：兩篇 GFW 研究都 implicitly 假設 Internet 7-priority 結構（survivability 第一）的存在——這是為什麼 GFW 必須做 in-path inspection 而非 architectural denial
- **直接 inform** Phase III 11.1 威脅模型——把「Internet 是 survivable + accountability-free」作為 threat model 的 axiom
- **直接 inform** Phase III 12.22 論文 intro——解釋為什麼「翻牆協議能存在」是 Internet design 的副作用，不是「破壞」Internet
