# Congestion Avoidance and Control

**Venue / Year**: ACM SIGCOMM '88, Stanford CA, August 1988. Reprinted in ACM SIGCOMM Computer Communication Review (CCR) January 1995. DOI [10.1145/52324.52356](https://doi.org/10.1145/52324.52356).
**Authors**: Van Jacobson (Lawrence Berkeley Laboratory), with credit to Michael J. Karels for related implementation
**Read on**: 2026-05-14（in lesson [1.9 TCP 可靠傳輸](../../lessons/part-1-networking/1.9-tcp-reliable-delivery.md)，將再次在 [1.10 TCP 擁塞控制](../../lessons/part-1-networking/1.10-tcp-congestion-control.md)中精讀）
**Status**: Full PDF freely available at LBL mirror <https://ee.lbl.gov/papers/congavoid.pdf>. Author's own revised version (post-publication footnotes) included. Content is paradigmatic, cited 14,000+ times.
**One-line**: 1986 internet 出現第一次「congestion collapse」（LBL 到 UC Berkeley 從 32 Kbps 跌到 40 bps）；Jacobson 在 4.3BSD TCP 內加入 7 個 algorithm（**conservation of packets** 為核心原則 + **RTT variance estimator** + **exponential RTO backoff** + **slow-start** + **dynamic window sizing** + **Karn's clamped retx backoff** + **fast retransmit**），徹底解決 internet 不穩定，**奠定過去 40 年所有 TCP/QUIC congestion control 與 reliable delivery 演化的基礎**——是 internet engineering 必讀文獻 No.1。

## Problem

1986 年 10 月：internet 首次大規模 **congestion collapse**——LBL 到 UC Berkeley（物理距離 400 yards、3 個 IMP hops）的有效吞吐量從 32 Kbps 跌到 **40 bps**——**降低 1000 倍**。Jacobson 與 Mike Karels 受此事件刺激，調查為何 4.3BSD TCP 在惡劣網路下崩潰。

當時 TCP 缺乏：
- 對 network state 的 adaptive feedback
- RTT estimator 在變動環境下的 robustness
- retransmission timing 的科學基礎
- congestion 與 loss 的區分（兩者被 TCP 視為同一回事）
- 多流之間的 fairness mechanism

⇒ Internet **沒有 self-stabilizing 機制**，任何高負載都可能 cascading collapse。

## Contribution

**7 個演算法（後續 40 年所有 TCP 改進的 root）**：

#### (i) Round-trip-time variance estimation

不只算 SRTT，也算 RTTVAR。**RTO = SRTT + 4×RTTVAR**（原 paper 用 2×，**revised version 改為 4×**——這個 change 是 Jacobson 自己在後續修訂加的 footnote，因為觀察到 slow SLIP link 的 spurious retx）。

```
SRTT_n   ← (1-α) × SRTT_{n-1}   + α × R_n           α = 1/8
RTTVAR_n ← (1-β) × RTTVAR_{n-1} + β × |SRTT - R_n|  β = 1/4
RTO_n    ← SRTT_n + max(G, 4 × RTTVAR_n)
```

**奠定**：所有 TCP variant 至今仍用此公式。後續微調（RFC 6298、RFC 7323）只在 boundary case 加 clamp。

#### (ii) Exponential retransmit timer backoff

連續 retx 後 RTO 必須 doubling（×2）：第一次 RTO，第二次 2×RTO，...。**理由**：若 packet loss 是 congestion 信號，連續 loss 表示 congestion 嚴重——必須指數退避避免雪崩。

**Karn's clamped variant（algorithm vi）**：retx 期間**不更新** SRTT/RTTVAR（避免 ambiguity 污染 RTT estimator）。

#### (iii) Slow-start

新連線（或 RTO 後）**congestion window（cwnd）從 1 MSS 開始**，每收 ACK 加 1 MSS——**指數增長**直到 ssthresh（slow start threshold）。

```
cwnd_init = 1 MSS         (1988 default; 後續 RFC 3390 增到 ~4 MSS, RFC 6928 增到 ~10 MSS)
while cwnd < ssthresh:
    on each ACK: cwnd += 1 MSS
```

**理由**：新流不知 path capacity——保守起步，指數增長探出 BDP。

#### (iv) More aggressive receiver ACK policy

提早 ACK，避免 sender waiting；同時 delayed ACK（最多 200ms）減少 ACK 數量——平衡點 RFC 5681 後續 codify。

#### (v) Dynamic window sizing on congestion

congestion 時 **multiplicative decrease**（cwnd → cwnd/2），non-congestion 時 **additive increase**（cwnd += 1 MSS per RTT）。這就是 **AIMD（Additive Increase Multiplicative Decrease）**。**Chiu & Jain 1989** 後續 prove AIMD 是 distributed fairness 的最優解（下 lesson 詳）。

#### (vi) Karn's clamped retransmit backoff (Karn & Partridge 1987 algorithm)

cite 但作者明說 「**這是 Phil Karn 1987 work**」——非 Jacobson 原創，但他把 it integrate 進 TCP。

#### (vii) Fast retransmit

收到 3 個 dupACK → 立即重傳，**不等 RTO**——縮短 loss detection latency。

#### (viii) （後續 RFC 化）改進 Naghle algorithm 與 silly window avoidance

論文末段提到，soon-to-be-published RFC 處理（後成 RFC 1122）。

## Method (just enough to reproduce mentally)

#### "Conservation of packets" 核心原理

> "the flow on a TCP connection should obey a 'conservation of packets' principle. And, if this principle were obeyed, congestion collapse would become the exception rather than the rule. ... A new packet isn't put into the network until an old packet leaves."

意思：穩態下 sender 每收到 1 個 ACK（表示 1 個 packet 離開網路）才送 1 個新 packet——保持「**in-flight packet 數**」恆定。

**Self-clocking**：ACK 速率即 sender 的允許速率——天然反映 path capacity。

#### Slow-start 具體實作

```
on TCP connection start or after RTO:
    cwnd ← 1 MSS
    ssthresh ← 65535 (effectively unlimited)

while in slow-start (cwnd < ssthresh):
    on each new ACK:
        cwnd += 1 MSS

on packet loss detected:
    ssthresh ← cwnd / 2
    cwnd ← 1 MSS  (slow-start again)
```

⇒ 連續 RTT 內 cwnd 指數增長：1, 2, 4, 8, 16, ...

#### Congestion avoidance（after slow-start）

```
in congestion avoidance (cwnd ≥ ssthresh):
    on each new ACK:
        cwnd += MSS × (MSS / cwnd)     // 等價於每 RTT 加 1 MSS
```

每個 RTT 收到 cwnd/MSS 個 ACK，每個 ACK 加 MSS/cwnd——總加 1 MSS per RTT。**Additive Increase**。

#### Backoff on loss

```
on loss:
    ssthresh ← cwnd / 2
    cwnd ← cwnd / 2 (fast recovery, RFC 5681) or cwnd ← 1 (Tahoe original)
```

**Multiplicative Decrease**。

## Results

部署到 4.3BSD TCP 後（1988 起）：
- 1986 congestion collapse 後續再無大規模 internet collapse
- 1990s internet 從 ~1M user scale 到 100M user 仍 stable
- 所有 derived TCP variant（Tahoe / Reno / NewReno / Cubic / BBR / ...）都保留**conservation of packets** 原則

**對 internet 影響**：很可能是 single most cited paper in computer networking。**現代 internet 能 scale 到 5B+ user 而不崩潰 = Jacobson 1988 算法直接結果**。

## Limitations / what they don't solve

作者本人後續坦白指出：

1. **AIMD 在高 BDP 上慢**：Jacobson 1988 對 1980s LAN/early WAN 設計——對現代 100 Gbps WAN cwnd 增長太慢。**Cubic (RFC 8312)、BBR (Cardwell 2017) 都是針對此** subsequent improvements
2. **混淆 congestion loss 與 random loss**：AIMD 假設「**loss = congestion**」——對 WiFi、衛星、cellular（random loss > 0）不適用——縮窗過度。**這推動了 explicit congestion notification (ECN, RFC 3168)、BBR delay-based、Hysteria Brutal 等替代**
3. **Fairness 僅在 RTT 相近時成立**：短 RTT 流自然搶到更多頻寬（cwnd 增長快）——不公平。**RTT-fair congestion control** 是 open research
4. **不考慮 multiple congestion 點**：path 上多個 bottleneck 時 AIMD 行為複雜
5. **無 anti-replay / cryptographic protection**：TCP 整體無法防 GFW-class adversary——後續 TCP-AO 部分補
6. **Loss detection 在 short flow 失效**：fast retransmit 需要 3 dupACK——short flow 無法觸發。**RACK-TLP (RFC 8985, 2021)** 是 33 年後的 fix
7. **Conservation of packets 對 application-limited flow 不適用**：sender 沒 data 填 cwnd 時行為 anomaly

## How it informs our protocol design

對 G6 / QUIC 的全部 reliable + congestion 設計都源於此：

1. **Conservation of packets 原則繼承**：G6 不能無限 burst——必須與 ACK 速率耦合
2. **AIMD 是 baseline**：QUIC CUBIC（QUIC RFC 9002 §7）= Jacobson 思想 + Ha 2008 Cubic 改進
3. **BBR 是 next-gen**：Cardwell 2017 BBR 完全跳過 packet conservation，改用 bandwidth/RTT 估計——**但仍尊重 AIMD 在 fair-sharing 場景的 role**
4. **G6 不能 100% 拋棄 AIMD**：若 G6 用「**自私**」congestion control（如 Hysteria Brutal），對共網其他流不公平——**有 ethical & practical implications**（會被 ISP / router 視為 abuse）
5. **slow-start 的「保守起步」哲學**：G6 連線開始時不能 burst 過量——避免被 GFW 偵測為 abnormal、避免造成 self-induced loss
6. **RTO 與 RTT estimator 必須 inherit Karn + Jacobson**：QUIC RFC 9002 直接 spec 此

## Open questions

- **AIMD 在 5G/LEO/WiFi-6 高 BDP + 高 variance link 上的適用性**：BBRv3、Copa、Vivace 等 active research，無 winner
- **多 sender selfish congestion control 的 game-theoretic 平衡**：若所有 sender 都用 Hysteria Brutal style，**outcome 是什麼**？open question
- **AI-tuned congestion control**：Indigo、Pantheon 等用 RL training congestion control——**可超越人類設計**嗎？部分證實 (Mvfst with custom CC) 但 deployment 仍小
- **PQ congestion control**：congestion control 本身無 crypto，但 ECN signaling 與 packet auth 互動有 open question
- **Conservation of packets 在 multipath（MPTCP/QUIC）下重新定義**：每 subflow 各自 packet conservation，跨 subflow coupling 如何？RFC 6356 部分 codify

## References worth following

- **Karn & Partridge 1987 SIGCOMM** — Karn's algorithm 原文
- **Chiu & Jain 1989 *Analysis of the Increase and Decrease Algorithms for Congestion Avoidance in Computer Networks*** — AIMD optimality 證明
- **Mathis, Semke, Mahdavi, Ott 1997 *Macroscopic Behavior of TCP Congestion Avoidance Algorithm***
- **Padhye et al. 1998 SIGCOMM *Modeling TCP Throughput***
- **Ha, Rhee, Xu 2008 *CUBIC: A New TCP-Friendly High-Speed TCP Variant***
- **Cardwell, Cheng et al. 2017 ACM CACM *BBR: Congestion-Based Congestion Control***（in [precis](.) 待寫）
- **RFC 5681 (TCP Congestion Control)** — Jacobson 1988 IETF codification
- **RFC 8312 (CUBIC)** + **RFC 9438 (CUBIC update 2023)**
- **RFC 9002 (QUIC loss detection & CC)**
- **Van Jacobson 個人 page at LBL** — 持續產出 networking paper
