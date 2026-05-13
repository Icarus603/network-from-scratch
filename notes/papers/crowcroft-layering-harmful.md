# Is Layering Harmful?

**Venue / Year**: IEEE Network Magazine 6(1), pp. 20-24, January 1992
**Authors**: Jon Crowcroft, Ian Wakeman, Zheng Wang, Dejan Sirovica (University College London + USWEST)
**Read on**: 2026-05-14 (in lesson 1.1)
**Status**: full PDF (5 pages) at `assets/papers/ieee-network-1992-crowcroft-layering-harmful.pdf`
**One-line**: 用一個真實的 BSD socket + TCP layering bug（4096-byte boundary 效能掉 3.5x）證明：**每一層各自正確的設計組合起來會產生錯誤的整體效能**——layering 對 modular 是好的，對 performance 是 hostile 的。

## Problem

當時 (1992) 的網路工程社群對 OSI / TCP/IP layering 一致接受。但作者在跑 RPC over TCP echo benchmark 時發現一個**奇怪的效能 cliff**：

```
資料量      RPC 完成時間
< 4000      ~0.3 sec
4096        1.4 sec   ← 突然慢 3.5x
> 5120      恢復正常
```

這個 glitch **不是 single layer 的 bug**——每個 layer 各自的 code 都是對的。問題出在**層間 interaction**。Crowcroft 想搞清楚：**為什麼？**

## Contribution

1. **完整 trace 出 layering bug 的根因**：用 `tcpdump` + `trace` (strace) debug 出 4096-byte glitch 是 **3 個正確設計的 unfortunate intersection**：
   - **BSD socket layer**：socket 有空間就把 user data 塞進去——即使空間只夠塞 small packet
   - **TCP sender (Nagle)**：「有 unacknowledged small packet 在飛時，不送新 small packet」——防止 silly window syndrome
   - **TCP receiver (delayed ACK)**：「不要每收到一個 packet 就立刻 ACK，等 200ms 看會不會 piggyback」——省頻寬
2. **三個正確 → 一個錯誤**：當 RPC 寫進 4096+96 byte：
   - 第二筆被 socket 切成 small packet 送出
   - Nagle 等 ACK
   - Receiver delayed ACK 等 200ms
   - **整體延遲爆炸 3.5x**
3. **提出「Silly Window Syndrome between layers」概念**：原本 SWS 是 TCP 內部的 bug；他們指出**socket layer ↔ TCP layer 介面**也有同樣 pattern——socket 太貪心地 advertise space，導致 TCP 送 small packet
4. **提出修法**（後來進 BSD Reno）：用 **low-water mark** 機制，socket 只在 buffer 空間 >= mark 時才 accept user data
5. **更廣的 architectural 結論**：引用 Clark & Tennenhouse 1990 的 ALF (Application Layer Framing) + ILP (Integrated Layer Processing)——主張**讓 application 直接控制 packet boundary**，不要被 layer 自己決定

## Method

**典型 systems debugging paper**：

1. 跑 RPC echo benchmark，發現 anomaly
2. 用 **`tcpdump`**（同時期 Van Jacobson 剛寫的）抓 packet trace
3. 用 **`trace`** (strace) 抓 system call 序列
4. 對照兩個 trace，pinpoint 到 socket buffer 與 TCP 互動
5. 看 BSD source code 確認推論
6. 重 build kernel 驗證 fix

對應 Saltzer 三步法：observation → hypothesis → controlled experiment to verify。

## Results

- 4096-byte glitch **完全可重現**：在 Sun3 / Sun SLC / HP400 各 platform 上都看到
- Fix 之後 RPC 效能 curve 變平滑（論文 Fig 7）
- 同樣 bug 在 BSD Reno (4.3-Reno) 已有 low-water mark fix；Solaris 也修了
- **發現 TCP_NODELAY (turn off Nagle) 不能完全修——因為 receiver 還是 delayed ACK**

## Limitations / what they don't solve

- **沒給 layering 的 quantitative cost model**——「strict layering 的 perf overhead 是多少」沒測
- **ALF/ILP 提案未驗證**：論文只 reference Clark & Tennenhouse 1990，沒實作 ALF 證明它解決了問題
- **5 頁論文太短**：很多 architectural critique 只有 1 段
- **沒處理 adversarial layer interaction**：「layering bug」是兩個 cooperative layer 互動出問題；當 layer 之一是 adversarial（middle-box, GFW）時，問題更深，論文沒涉及
- **時代侷限**：1992 沒 SDN、沒 P4、沒 ML-driven middlebox——layering 對抗 adversarial middle-box 是後來才嚴重的問題

## How it informs our protocol design

對 G6 設計的**警示性教訓**：

### 1. **「每層各自正確」不夠，必須整體測試**
- G6 = 加密 layer + 握手 layer + 流控 layer + 偽裝 layer
- 即使每個 layer unit test pass，組合後可能出 perf bug
- **Phase III 12.13 高丟包鏈路評測**就是要抓這類 layer interaction bug

### 2. **buffer boundary effects 是真實的**
- 我們協議設計時要明確定義「buffer / chunk / frame size」
- 跟 TCP MTU、TLS record、QUIC max_packet_size 對齊
- 不要重蹈 socket 4096 vs TCP 4096 的覆轍

### 3. **ALF / ILP 啟發**
- 我們協議的 frame size 應該由 **application semantics** 決定，不是 transport 隨意切
- QUIC 的 stream + frame 設計就是 ALF 思想——值得繼承
- Phase III 11.5 spec 設計 frame format 時應**對齊 application data unit**

### 4. **debug 方法論**
- Crowcroft 用 `tcpdump` + `strace` 對照——這正是 Phase III 12.x evaluation 要做的事
- **永遠在 packet trace + system call trace 雙視角下 debug**——只看一邊會誤判

### 5. **Layering 不是 binary 選擇**
- 不是「全 layered」或「全 monolithic」
- 而是「**層間介面該開哪些 hook**」——讓 application 能 hint lower layer，讓 lower layer 能 expose status 給 application
- TCP_NODELAY 是個粗糙 hint；現代 TLS / QUIC 有更精細的 hint API
- G6 也該設計**雙向 hint API**

## Open questions

- **Layering for adversarial environments**：1992 paper 處理 cooperative layer bug；當其中一個 layer 是 adversarial middle-box（GFW）時，layering 的 cost-benefit 完全不同——沒有系統性研究
- **ALF / ILP 是否真的取代 layering 了**？QUIC 採取了部分 ALF idea，但仍有 strict layer boundary（QUIC frame within QUIC packet within UDP datagram within IP）。完全 ALF 的 protocol（如 RDMA、SCTP）沒成為主流——為什麼？
- **ML-driven layer optimization**：能不能訓練一個 ML model 即時調整 layer interaction（buffer size、Nagle on/off、ACK timing）？2024+ 有 ML congestion control 工作（Aurora、ABC）——值得追
- **同樣的 bug 今天還會出嗎**？Crowcroft 報告的 glitch 在 Linux 6.x kernel + 現代 TCP 是否仍存在？我可以在自己 OrbStack VM 復現嗎？這是個 Phase 1.x 動手練習 candidate

## References worth following

論文 References 中對我們最 relevant：

- **Clark & Tennenhouse 1990** Architectural Considerations for a New Generation of Protocols (SIGCOMM 90) — ALF/ILP 提出，QUIC/HTTP3 的 intellectual ancestor
- **Nagle 1984** Congestion Control in IP/TCP Internetworks (RFC 896) — Nagle 演算法 ground truth
- **Clark 1982** Window and Acknowledgment Strategy in TCP (RFC 813) — delayed ACK 起源
- **Jacobson 1990** Tutorial on Efficient Protocol Implementation (SIGCOMM 90) — 同期 Van Jacobson 在 layering perf optimization 的 talk

延伸（不在 paper 引用）：
- **Saltzer-Reed-Clark 1984** End-to-End — 已建檔，e2e 是 layering 設計時的根本判準
- **Kohler 2000** Click Modular Router — 已建檔，把 layer 變 element 的工程答案
- **Floyd & Henderson 1999** RFC 2582 — TCP NewReno，Nagle/SACK 互動的下一輪修
- **Chu et al. 2013** Increasing TCP's Initial Window (RFC 6928) — 現代 TCP 對 Nagle/SWS 互動的最新思考
- **Cardwell et al. 2017** BBR (CACM) — 用 model-based 取代 Nagle/CUBIC，對 layer interaction 的更激進修法

## 跨札記連結

- **與 Saltzer 1984**：Crowcroft 證明「strict layering 在 e2e 框架下也會出 bug」——layering ⊂ e2e 但 layering ≠ e2e。Saltzer 從未主張 strict layering；Crowcroft 替他補刀
- **與 Clark 1988 DARPA Design**：Clark 描述 Internet 的 layering 是設計選擇之一，而 Crowcroft 揭露這個選擇有 hidden cost
- **與 Click 2000**：Click 把 strict layer 拆成可組合 element，是 Crowcroft 警告的工程解法——「layering harmful 嗎？答：strict layering 是；可組合的 layer 不是」
- **直接 inform** Phase III 11.5 spec 設計時 frame size 必須跟 application data unit 對齊
- **直接 inform** Phase III 12.13 高丟包鏈路評測時要找 layer interaction bug
- **直接 inform** Phase III evaluation 工具鏈——packet trace + system call trace 雙視角是 standard
