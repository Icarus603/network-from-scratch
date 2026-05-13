# End-to-End Arguments in System Design

**Venue / Year**: ACM Transactions on Computer Systems 2(4), pp. 277-288, November 1984. Earlier version at Second Int'l Conf. on Distributed Computing Systems, Paris, April 1981.
**Authors**: J.H. Saltzer, D.P. Reed, D.D. Clark (MIT Laboratory for Computer Science)
**Read on**: 2026-05-14 (in lesson 1.1)
**Status**: full PDF (10 pages) at `assets/papers/tocs-1984-saltzer-end-to-end.pdf`
**One-line**: 設計分散式系統時，把功能放在低 layer 通常**只是 performance hint，不能取代端點實作**——因為許多功能本質上「只能」在端點做完整且正確。

## Problem

設計分散式系統時，每一個功能（reliable delivery / encryption / FIFO ordering / duplicate suppression / acknowledgement / crash recovery）都有兩個放法：放在 **lower communication subsystem** 或放在 **end-point application**。

當時（1981–84）的典型答案是「放低層」——OSI 7 層、ARPANET RFNM、virtual circuit 都這樣做。**但這真的對嗎？**

## Contribution

提出 **end-to-end argument**：

> **The function in question can completely and correctly be implemented only with the knowledge and help of the application standing at the end points of the communication system. Therefore, providing that questioned function as a feature of the communication system itself is not possible. Sometimes an incomplete version of the function provided by the communication system may be useful as a performance enhancement.**

也就是：**對某類功能，lower-layer 提供它最多是 performance hint，不能取代 end-point 的實作**。

論文用 **6 個範例**示範這個論證：

1. **Reliable file transfer**（核心案例）
2. **Delivery acknowledgement**（ARPANET RFNM 為例）
3. **Encryption**（authenticity vs confidentiality 拆開）
4. **Duplicate message suppression**（application-level dup 下層擋不到）
5. **FIFO message delivery**（跨 connection 的 ordering 下層做不到）
6. **Transaction management** (SWALLOW 案例：丟棄低層的多餘保證後 message 數量減半)

## Method

純 **architectural argument paper**——沒實驗。靠 reasoning + 6 個 case study + 1 個 MIT 真實 bug（gateway byte-swap）說服讀者。

**MIT bug 案例（最有殺傷力的證據）**：MIT 一個 gateway 因 hardware fault 每 ~1M byte 交換一對 byte。**儘管每個 hop 都有 packet checksum**（hop-by-hop reliability），bug 仍 silently 腐化大量 source code——直到有人手動跟舊 listing 對照才發現。

→ **存在性證明**：hop-by-hop reliability ≠ end-to-end reliability。

## Results

論文無量化結果（不是實驗論文），但**對學界影響極大**：
- IAB 把 end-to-end 寫進 RFC 1958 *Architectural Principles of the Internet*
- Internet 的 stateless router、應用層 retry、TCP 端點 checksum 等設計都繼承這論點
- 後續 30 年 networking 教科書必引

## Limitations / what they don't solve

- **沒給 quantitative model**——「performance hint 多少效益值得」沒形式化
- **「end」如何識別**完全靠 designer judgment（作者自己舉了 voice transmission case 承認這點：real-time conversation 跟 voicemail 的「end」不一樣）
- **不適用 PEP / middlebox 主流化的情境**（衛星鏈路 PEP、mobile network 的 middle-box 都「違反」end-to-end 但有 perf 必要性）
- **沒處理 active adversary**：論文假設中間 box 是 cooperative or dumb，**沒考慮中間 box 是 adversarial**（GFW 場景）
- **時代局限**：1984 沒有 ML，沒有 ECH，沒有 QUIC

## How it informs our protocol design

對 G6 的**根本性影響**：

### 1. **「End」的明確定義**
- G6 的兩個 endpoint = 用戶 client + 用戶 server（VPS）
- **GFW、ISP、中繼節點、CDN 都不是 endpoint**
- 因此：**anti-detection 必須在端點做**，無法 outsource 給任何中間元件

### 2. **加密 + 認證 拆開**
- Saltzer 明確指出：通訊系統做加密不能取代 application-layer authentication
- G6 雖是 transport-layer encryption，**仍須在握手時做端點 authentication**（避免 MITM）
- 這直接影響 Phase III 11.5 spec 的 handshake 設計

### 3. **避免「過度承諾」**
- G6 不該承諾「reliable delivery」——這是 application 該做的事
- G6 該承諾的是「**unobservable transport**」——這是 application 做不到、必須由我們負責的功能
- 把 reliable / ordered 等保證下放到 QUIC 層（如果走 QUIC），不要在 G6 protocol 層重做

### 4. **「performance hint」的合理使用**
- G6 內部可以做 reliability enhancement（loss recovery、FEC）作為 perf hint
- 但**不該假設 application 不做 retry**——application 仍要在 timeout 後 retry
- 對應 Saltzer 的「low level 是 perf enhancement，不是 correctness substitute」

### 5. **與 anti-censorship 的張力**
- Saltzer 的 framework **沒考慮 adversarial middle-box**
- 我們協議要對抗 GFW = 對抗 adversarial middle-box
- 這需要我們**擴展** Saltzer 的 framework：把「anti-detection」加進「只能在端點做」的 list
- → 這是 Phase III 11.1 威脅模型撰寫時的核心 framing

## Open questions

- **End-to-end 在 ML adversary 時代怎麼擴展**？Saltzer 假設中間 box 是 dumb，但 GFW 用 ML 識別流量——「dumb forwarder」假設崩塌後，end-to-end 還是足夠的設計指南嗎？
- **PEP / TCP accelerator 的 ROI**：在衛星鏈路、行動網路上，**違反 end-to-end** 的 middle-box 確實能加速。我們協議要不要學？比如做 server-side PEP？
- **「End」可以是多個 entity**：one-to-many broadcast 場景下，每個 receiver 都是 end，端點 ack 變得不可行——multicast / RTP 怎麼套 end-to-end argument？
- **形式化的 layering algebra**：能不能定義「funcation F 在 layer L 上是 end-to-end-required vs perf-hint-only」的形式判別？目前完全 informal

## References worth following

論文 §History 與 References 摘出對我們最 relevant：

- **Branstad 1973** Security aspects of computer networks (AIAA) — encryption end-to-end argument 的最早 publicly discussed
- **Diffie & Hellman 1976** New Directions in Cryptography — 後來成為 G6 的 key exchange 基礎
- **Needham & Schroeder 1978** Using encryption for authentication — application-level auth 的開山
- **Reed 1978 dissertation** Naming and Synchronization in a Decentralized Computer System — fate sharing 理論基礎
- **Lampson & Sproull 1979** An open operating system for a single-user machine — 「functions should be replaceable」的延伸
- **Gray 1978** Notes on database operating systems — two-phase commit 的端點論證
- **Schroeder, Clark & Saltzer 1977** Multics kernel — 把 function 從 low layer 提到 high layer 的工程實踐

延伸（不在 paper 引用裡的）：
- **Clark 1988** The Design Philosophy of the DARPA Internet Protocols (SIGCOMM 1988) — 已建檔，把 e2e 放進 7-priority 的 framework
- **Crowcroft 1992** Is Layering Harmful — 已建檔，從反方向質疑 layering 設計
- **RFC 1958** Architectural Principles of the Internet (Carpenter 1996) — IAB 把 e2e 寫成 IETF 立場
- **van Schewick 2010** Internet Architecture and Innovation — 把 e2e 從工程拉到法律/政策層級

## 跨札記連結

- **與 Clark 1988**：Clark 的 DARPA design 7-priority 是 e2e 的實際應用——survivability 第一推導出 fate sharing，fate sharing 推導出端點儲存 connection state，這就是 e2e 的具體 architecture
- **與 Crowcroft 1992**：Crowcroft 反過來指出 e2e 嚴格分層在實作時會出 bug——layering 並不是 e2e 的同義詞，e2e 比 strict layering 更 nuanced
- **與 Click 2000**：Click 的 element 設計繼承 Lampson 「functions should be replaceable」精神——是 e2e 的 router-side 實作
- **直接 inform** Phase III 11.1 威脅模型撰寫時對「端點」的明確定義
- **直接 inform** Phase III 11.4 主架構決策時對「加密 + 認證」拆開的設計選擇
- **直接 inform** Phase III 11.5 spec handshake 設計時對 endpoint authentication 必要性的論證
