# BBR: Congestion-Based Congestion Control

**Venue / Year**: ACM Queue Vol. 14, No. 5, September-October 2016. Reprinted in Communications of the ACM (CACM) Vol. 60, No. 2 (February 2017). DOI [10.1145/3009824](https://doi.org/10.1145/3009824).
**Authors**: Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh, Van Jacobson (all Google)
**Read on**: 2026-05-14（in lesson [1.10 TCP 擁塞控制](../../lessons/part-1-networking/1.10-tcp-congestion-control.md)，將再次於 [1.9](../../lessons/part-1-networking/1.9-tcp-reliable-delivery.md) 與 Part 8 QUIC 章節 reference）
**Status**: CACM full text accessible via paywall-free Google Research mirror. ACM Queue version freely available. Subsequent IETF drafts (BBRv2 ICCRG IETF 104, BBRv3 IETF 117) cross-checked. Ware 2019 IMC critical assessment also included.
**One-line**: 跳出 1988 Jacobson 「**packet loss = congestion**」典範——把 congestion control 重新定義為「**估出 bottleneck bandwidth 與 round-trip propagation time、跑在 BtlBw × RTprop 的最佳操作點**」的模型驅動演算法；對高 BDP / lossy link 比 CUBIC throughput +2~25×、global median RTT -53%；Google B4 WAN 與 YouTube 全面部署；同時引發 fairness 爭議，BBRv2/v3 持續修補。

## Problem

CUBIC（2008）雖然解了 high-BDP 增長問題，但仍是 **loss-based**：把 packet loss **等同**於 congestion 信號。1988 年的這個設計假設在 2010s 已破：

1. **Bufferbloat**（Gettys 2011）：modern router 大量過大 buffer → loss-based CC 把 buffer 撐滿才縮窗 → RTT 飆到秒級
2. **Lossy link**（WiFi、cellular、衛星）：random loss 不來自 congestion → loss-based CC 過度縮窗 → throughput 暴跌
3. **High BDP**：BDP 100 MB+ 的 path 在 1% loss 下 Reno-style CC 幾乎無法達線速（Mathis equation）
4. **Asymmetric link**：upload/download 不對稱 + ACK 路徑 buffer 也滿 → loss/RTT 信號互相污染

Google 跑 B4 WAN（自家骨幹）與 YouTube：**用 CUBIC 持續看到 sub-optimal throughput + 高 RTT**。**Cardwell 等 3 年研究尋找新典範**。

## Contribution

#### 1. 重新定義 CC 目標

不是「**最大化 cwnd 直到 loss**」，而是「**穩在 BDP 操作點 = max throughput + min queueing**」。

形式化：
- **BtlBw** (Bottleneck Bandwidth) = max throughput possible on path
- **RTprop** (Round-Trip propagation time) = pure physical RTT, no queueing
- **BDP** = BtlBw × RTprop = optimal in-flight data

**最佳操作點 = (BDP in-flight, BtlBw sending rate)** → throughput = BtlBw, queueing = 0.

#### 2. Uncertainty principle of measurement

BtlBw 與 RTprop 不能同時量：
- 量 BtlBw → 必須 fill pipe → queueing → RTT > RTprop
- 量 RTprop → 必須 drain pipe → in-flight < BDP → throughput < BtlBw

⇒ BBR 設計**交替量測**，**filter** 各自的 max (BtlBw) / min (RTprop) over time window。

#### 3. State machine

```
STARTUP → DRAIN → ProbeBW (main) ⇄ ProbeRTT (periodic)
```

- **STARTUP**：pacing_gain = 2/ln2 ≈ 2.89，binary search BtlBw；當 delivery rate 不再增長視為達 BtlBw → DRAIN
- **DRAIN**：pacing_gain = ln2/2，排空 STARTUP 累積的 excess queue
- **ProbeBW**：穩定狀態，pacing_gain cycles `[1.25, 0.75, 1, 1, 1, 1, 1, 1]`（8 個 RTprop interval 一個 cycle）；1.25 探 BtlBw 增加、0.75 排出可能 queue
- **ProbeRTT**：每 10 秒一次，cwnd = 4 MSS、drain pipe，量 RTprop。持續 200ms。

#### 4. Pacing instead of cwnd-only

傳統 TCP 依 cwnd 釋放 packet（burst-like）。BBR **pacing**：均勻分散 over RTprop 間隔——避免 bursty queueing。

需 Linux fq qdisc 或 socket-level pacing。**這是 BBR 部署的硬性要求**。

#### 5. 可預測 throughput response

對 BtlBw 增加（如其他 flow 退出），BBR 在**指數 ProbeBW** time 內 catch up（vs Reno 線性、CUBIC 多項式）。

對 RTprop 增加（如 path 改變），BBR 在 1 個 ProbeRTT cycle 內 detect 並 update。

## Method (just enough to reproduce mentally)

#### 核心 measurement

每收到 ACK：
- 算 `instantaneous_delivery_rate = data_acked / time_elapsed`
- 算 `instantaneous_rtt = now - departure_ts(highest_acked_packet)`
- 更新 BtlBw filter (max over 10 RTT window)
- 更新 RTprop filter (min over 10 sec window)

#### cwnd 與 pacing

```
target_cwnd = BtlBw × RTprop × cwnd_gain   (cwnd_gain ≈ 2 for steady state)
pacing_rate = BtlBw × pacing_gain
```

cwnd 限定 in-flight 不超過 2×BDP（防 burst）；pacing_rate 控釋放速率。

#### 不依賴 loss-based 信號

BBR 對 loss 反應**不縮窗**——loss 視為 path 屬性，不視為 congestion signal。**這是 paradigm shift 的核心**。

## Results

#### Google B4 WAN deployment

- 跨大洲 backbone：throughput **+14%** average，個別 path **+133×**
- 部署時間：2016 fully migrated

#### YouTube CDN

- **throughput**：median **+4%**，發展中國家 **+14%**
- **RTT**：median **-53%**，發展中國家 **-80%**
- **rebuffering**：減少約 33%

#### Lab measurement

- 1 Gbps × 100 ms BDP path：
  - CUBIC：~15 Mbps (saturated by receive buffer)
  - BBR：~2 Gbps (after increasing receiver buffer)
  - **133× speedup**

#### Linux kernel integration

- Linux 4.9 (Dec 2016) mainline
- 全球 Linux server **~23% 用 BBR**（Mishra 2020 census）
- Linux 5.x+ 包含 BBRv2

## Limitations / what they don't solve

#### 1. Fairness 嚴重問題（Ware et al. 2019 IMC ⭐）

**BBR vs CUBIC 共存**：BBR 單流與 16 個 CUBIC flow 共存時：
- BBR 占 **~40% 頻寬**（公平應 ~6%）
- 原因：BBR 不對 loss 縮窗——CUBIC 一旦 loss → 縮窗 → BBR 反而擴張

實質**全網部署 BBR 會引發 race-to-bottom**——人人都用 BBR 才能保持 throughput。

#### 2. 多 BBR flow 共存的 oscillation

兩個 BBR flow 同 bottleneck：ProbeBW pacing_gain cycle 可能同步 → 同時 1.25 → queue 同時 spike → RTprop 估算錯——**oscillation**。

#### 3. ProbeRTT 對 latency 敏感應用造成 jitter

每 10 秒一次 cwnd = 4 MSS 排空——對 video conferencing / real-time 應用造成可感知 RTT spike。

#### 4. 對 ECN 不 native 支援

BBRv1 純 model-based，**忽略 ECN signal**。在 ECN-deployed network 無法協作。

#### 5. Bursty loss 與 random loss 無法區分

BBR 對任何 loss 反應都一樣（基本忽略）——但**真實 congestion-induced loss** 應該縮窗。BBRv1 在這點上 too aggressive。

⇒ **BBRv2 / BBRv3 修補上述 1-5**：加 ECN signal、加 loss-rate cap、改 ProbeBW 隨機化、改 ProbeRTT 頻率。

## How it informs our protocol design

對 G6：

#### 1. Baseline CC = BBR v3 if available

BBR throughput 優勢在 G6 場景（typically lossy international link）**極顯著**——CUBIC 不適合。

#### 2. Fallback CC = CUBIC

某些受限環境（fq qdisc 不 available、kernel 不支援 BBR）必須 fallback。

#### 3. Pacing 是 mandatory

G6 server side：Linux fq qdisc enabled by default。Client side：應用層 pacing（QUIC 內建）。

#### 4. ProbeRTT 對 G6 anti-fingerprinting 影響

每 10 秒 cwnd 縮到 4 MSS——**packet rate pattern 變化**——可能被 GFW 識別為 BBR 特徵。**G6 應該 jitter ProbeRTT 週期 + 偽裝 cwnd drop**。

#### 5. Brutal 是 BBR 的反向思路

BBR 假設 loss 可能 random 但仍**有限度地** respect path。Brutal 完全**不 respect**。**G6 提供 opt-in Brutal 但 default 走 BBR** 是 ethical & technical balance。

## Open questions

- **BBRv3 的 fairness 是否足夠**：仍有 academic critique；real-world deployment 量測缺
- **BBR 與 AQM (CoDel/PIE) 互動**：theoretical 應該好，實測有 anomaly
- **AI-tuned BBR**：用 RL 動態調 pacing_gain cycle——可超越 hand-tuned constant？
- **BBR 在 LEO satellite + Starlink 場景**：高 RTT variance、handoff 頻繁——BBR 對 RTprop 估算錯（min filter 卡 old value）需要新 mechanism
- **post-quantum BBR**：CC 算法本身無 crypto，但 pacing 信號（timing）可能洩漏 keying material 之 side channel——open
- **多 path BBR**：MPTCP / multipath QUIC 各 subflow BBR 互動仍 active research
- **BBR fingerprint 對審查的影響**：BBR distinctive pacing pattern 是否成為 G6 識別 vector？open
- **L4S 整合**：BBR 走 model-based, L4S 走 ECN-fine-grained——**兩者統合**是 open architectural 問題

## References worth following

- **Cardwell 2017 BBR CACM** 全文 — 必精讀
- **Cardwell BBRv2 IETF 104 slides + draft**
- **BBRv3 IETF 117 (2023) presentation**
- **Linux source `net/ipv4/tcp_bbr.c`** — reference implementation
- **Hock et al. 2017 *Experimental Evaluation of BBR Congestion Control***
- **Ware et al. 2019 IMC** ⭐ — fairness critique
- **Modi et al. 2020 *BBR Congestion Control: IETF 110***
- **APNIC blog Geoff Huston BBR 系列**
- **Pantheon project Yan 2018 USENIX ATC** — CC benchmark with BBR
- **The Great Internet TCP Congestion Control Census Mishra 2020 SIGMETRICS** — production deployment census
- **Kakhki et al. 2018 IMC *Taking a long look at QUIC***——含 BBR-in-QUIC 量測
