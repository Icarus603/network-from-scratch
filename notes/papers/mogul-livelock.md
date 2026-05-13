# Eliminating Receive Livelock in an Interrupt-driven Kernel

**Venue / Year**: ACM Transactions on Computer Systems 15(3), August 1997, pp. 217-252. Earlier version at USENIX ATC 1996.
**Authors**: Jeffrey C. Mogul (DEC Western Research Lab), K. K. Ramakrishnan (AT&T Bell Labs)
**Read on**: 2026-05-14 (in lesson 1.2)
**Status**: full PDF (13 pages, truncated extract) at `assets/papers/tocs-1997-mogul-livelock.pdf`
**One-line**: 1990s 中網路速度衝破 100 Mbps 後，純 interrupt-driven kernel 在高 packet rate 下會**反直覺地崩潰到 0**（receive livelock）；提出 polling + cycle-limit feedback 的混合設計——這是後來 Linux NAPI 的設計基礎。

## Problem

1996 年的 BSD-derived UNIX kernel 用 **pure interrupt-driven** 處理網路 packet：每個 packet 到達 → NIC interrupt → CPU 跳進 interrupt handler → 處理 packet → 回 user space。

當網路速度從 10 Mbps 漲到 100 Mbps，packet rate 從 ~1000 pps 漲到 ~10000 pps，**這個設計崩潰**：
- CPU 100% 時間都在 interrupt context
- 沒時間讓 IP stack 把 packet 從 input queue 拉出來
- 沒時間給 user app 跑
- **吞吐量降到 0**（livelock，不是 deadlock——系統還在跑，但沒做有用工）

**反直覺**：負載越高 → 吞吐量越低（不是飽和 plateau）。

## Contribution

1. **形式化定義 "Receive Livelock"**：「系統不在 deadlock 狀態，但因 packet-input handling 持續搶佔所有 CPU，導致實際吞吐量為零」
2. **量化 livelock 在 4.2BSD-based UNIX 上的真實發生**（DECstation 3000/300 routing test）：
   - 輸入 0~2000 pps → 線性 forwarding
   - 輸入 4000 pps → peak ~4700 pps output
   - 輸入 6000+ pps → forwarding rate 崩潰到 ~1500 pps 並繼續下降
   - 配上 user-mode firewall (screend) → 完全 livelock 到 0
3. **三個獨立但常被混淆的 overload 問題**：
   - **Receive livelock**（delivered throughput 降到 0）
   - **Increased packet delivery latency**（first packet of a burst 被 link-level processing 整個 burst 延遲）
   - **Transmit starvation**（CPU 跟得上 input 但沒空跑 transmit）
4. **解法：5 個技術組合**：
   - **Interrupt rate limiting**：偵測 livelock 後暫時 disable input interrupt
   - **Polling**（only after interrupt）：interrupt 只 trigger polling thread；polling 處理 packet 直到 quota 用完
   - **Process to completion**：一旦 commit 處理某 packet，跑完整個 stack，不在中間 queue
   - **Explicit CPU usage control**：cycle-limit feedback；packet processing 超過某 % CPU 時 disable input
   - **Early packet drop**：queue 滿時直接 disable input interrupt 而非繼續收
5. **量化解法效果**：跟 unmodified kernel 對比（Fig 6-3, 6-4）；解法後即使輸入 10000+ pps，output 維持在 4700 pps 平穩（無 livelock）；with screend，從崩潰到 0 修正到穩定 ~2800 pps

## Method

**Empirical systems performance paper**：

1. **Production-realistic setup**：DECstation 3000/300 Alpha + Digital UNIX V3.2 + 2x Ethernet。Router-under-test 是故意選慢的 Alpha 機型，模擬 saturated CPU 場景
2. **Quantitative metrics**：forwarding rate (pkts/sec)、output rate、CPU 可用 cycles
3. **Phantom destination** (用假 ARP entry) → 不需真實 destination 也能 stress test
4. **Trace each kernel modification**：unmodified → +polling no quota → +polling quota → +polling+feedback → +cycle limit
5. **Vary quota / threshold**：找出 quota=10-20 packets, threshold=50% CPU 是 sweet spot

## Results

| 配置 | 6000 pps 輸入下的 output rate |
|---|---|
| Unmodified 4.2BSD | ~3000 pps（下降中） |
| + Polling, no quota | ~0 pps（input queue 滿，新 packet 持續丟） |
| + Polling, quota=10 | ~4700 pps（穩定） |
| + Cycle limit feedback | ~4700 pps + user CPU 不再餓死 |

**穩定性是核心成果**——不是 peak throughput 提升，是「**輸入 10000 pps 時仍 output 4700 pps 而非崩潰到 0**」。

## Limitations / what they don't solve

- **沒處理 transmit-side starvation 的根因**（只 mitigate）
- **Quota / threshold 的最佳值是 hardware-dependent**——論文做 sensitivity analysis，但每個系統要重 tune
- **沒實現整合到 high-speed driver**（FDDI、Gigabit）——當時最快測試介面是 100 Mbps Ethernet
- **沒涉及多核**——1996 主流 single CPU；現代多核 + RSS 是新 dimension（後來 Linux NAPI 解決）
- **預設 packet 都該處理完**——丟棄策略沒有跟協議層協作（後來 RED / AQM 補上）

## How it informs our protocol design

對 G6 的**根本性背景知識**：

### 1. **G6 server 在高負載下不會 livelock**
- Linux NAPI 是 Mogul 思想的 production 實作
- 我們無需在 G6 application code 處理 livelock——kernel 已解決
- **但**：如果用 DPDK / netmap 完全 bypass kernel，要自己負責 polling + quota 設計

### 2. **Packet rate 是 throughput 上限**
- Phase III 12.4 設計時要算 packet-per-second 而非 bps
- 1500 byte packet @ 5 Gbps ≈ 416 Kpps；64 byte packet @ 5 Gbps ≈ 9.7 Mpps（後者極難達到）
- **協議設計影響 packet rate**：如果 G6 多用小 packet（為 anti-fingerprinting）→ packet rate budget 緊張

### 3. **Mogul 5 技術組合是 modern packet IO 設計的祖譜**
- DPDK = polling + process-to-completion + no kernel context（完全脫離 interrupt）
- AF_XDP = NAPI + zero-copy（混合）
- io_uring = batched syscall + completion model（Mogul "polling thread" 的 syscall API 化）
- G6 不論選哪個，**都是 Mogul 1997 的後代**

### 4. **Cycle-limit feedback 也適用協議內部**
- 我們 G6 內如果做 inline DPI (anti-fingerprinting evaluation)，應該也有 cycle limit
- 避免 application-level livelock：太多時間花在分類 → 沒時間 forward

### 5. **Early drop = anti-DoS**
- GFW 主動探測或 DDoS 場景下，G6 server 必須 early drop 而非 try to process all
- nftables / eBPF 在 driver level drop 比 application drop 省 10x CPU

## Open questions

- **Multi-core livelock**？多核時代沒人重做 livelock 實驗，但理論上每 core 仍可能 livelock；RSS 把 packet 散到多核**減輕**但不消除問題
- **GPU offload 跟 NIC offload 的 livelock 對應物**？2024+ ML packet classification 跑在 GPU 上，GPU 也有 receive livelock 嗎？
- **NUMA + livelock 互動**？跨 NUMA 的 packet path 多 100ns 延遲，更容易 livelock，但沒有正式 study
- **eBPF program 內 livelock**？XDP program 跑在 driver context，本質上是 interrupt context；高負載下 XDP 是否能 livelock？開放
- **AI workload 跟 packet IO 競爭**：GPU 跑 inference 同時 process packets 時的調度策略——AI 時代的新 livelock 變體

## References worth following

論文引用中對我們最 relevant：

- **Floyd & Jacobson 1993** Random Early Detection (RED) — 論文 ref [3]，AQM 的 packet drop 策略
- **Jacobson 1990** Efficient Protocol Implementation (SIGCOMM tutorial) — ref [4]，TCP fast path
- **Mogul 1989** Simple and Flexible Datagram Access Controls — ref [7]，screend firewall
- **Ramakrishnan 1992** Scheduling Issues for Interfacing to High Speed Networks — ref [11]，同作者前作
- **Smith & Traw 1993** Giving Applications Access to Gb/s Networking — ref [14]，user-level networking 早期工作

延伸（不在 paper 中）：
- **Linux NAPI documentation** in kernel source — Mogul 1997 的工程實作
- **Rizzo 2012 netmap** — 已建檔，takes Mogul 進一步到 zero-copy
- **Høiland-Jørgensen 2018 XDP** (CoNEXT) — XDP = Mogul polling 思想 + eBPF
- **DPDK Programmer's Guide** — full poll-mode driver 設計

## 跨札記連結

- **與 Rizzo 2012 netmap**：Mogul 解決 interrupt overhead，但仍有 sk_buff alloc / syscall / memcpy 三個 overhead；netmap 用 zero-copy + batch 解決剩下三個
- **與 Han 2012 MegaPipe**：兩個獨立攻擊不同層級——Mogul 解 driver/interrupt 層，MegaPipe 解 socket API 層；兩者組合就是 modern 高效能 server
- **與 Neugebauer 2018 PCIe**：Mogul 解 CPU side livelock；Neugebauer 揭露 PCIe bus 本身才是現代瓶頸——四篇形成完整的「packet 處理 cost 階梯」
- **與 Crowcroft 1992 Is Layering Harmful**：Mogul 是 Crowcroft 警告的「strict layering 出 bug」之一具體 case——interrupt prio + queue layering 在高負載下出 bug
- **直接 inform** Phase III 12.4 G6 資料路徑設計選擇
- **直接 inform** Phase III evaluation 對 packet-rate 限制的理解
