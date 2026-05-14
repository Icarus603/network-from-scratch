# Piece of CAKE: A Comprehensive Queue Management Solution for Home Gateways

**Venue / Year**: IEEE LANMAN 2018 / arXiv:1804.07617  
**Authors**: Toke Høiland-Jørgensen, Dave Täht, Jonathan Morton  
**Read on**: 2026-05-14（in lesson [2.13 tc / netem](../../lessons/part-2-high-perf-io/2.13-tc-netem.md)）  
**Status**: full PDF（`assets/papers/ton-2018-cake.pdf`）  
**One-line**: fq_codel 後繼者 — 把 fair queueing + AQM + bandwidth shaping + ISP overhead 補償整合進單一 qdisc，是家用 / OpenWrt SQM 的事實標準。

## Problem

fq_codel (Høiland-Jørgensen 2018 RFC 8290) 已解 bufferbloat，但 deployment 在家用 router 仍要組合：

- fq_codel + HTB 才能 shape bandwidth
- 不處理 ISP-side framing overhead（PPPoE / DOCSIS）
- per-flow 但不 per-host（一個 host 跑多 flow 會壓住其他 host）
- 多層 wrap 增 lookup overhead

需要 **一站式家庭 router AQM solution**。

## Contribution

1. **Cobalt AQM**：CoDel + BLUE 混合，對 buffer overflow + 流量爆發雙重響應
2. **多 tier fairness**：per-flow within host + per-host fair
3. **內建 shaping**：bandwidth knob 直接設，無需外 wrap HTB
4. **DiffServ-aware**：DSCP marking 分 priority tier（Bulk / Best Effort / Video / Voice）
5. **Overhead compensation**：對 PPPoE / VDSL2 / DOCSIS / ATM 等 ISP framing 算進 bandwidth budget
6. **8-way set-associative hashing**：對 hash collision 比 fq_codel 線性 robust

## Method

- 在 sch_cake.c 實現為 Linux qdisc
- 雙層 hashing：first hash 16K bins → 8-way set associative
- 對每 set 跑 Cobalt AQM
- DiffServ shapers in parallel

## Results

- 對 RRUL test 在 1Gbps DOCSIS 鏈路 P99 latency under load 比 fq_codel 進一步降 30%
- per-host fairness：1 host A 100 flow vs host B 1 flow 場景，仍能 50:50 share
- OpenWrt SQM-scripts 預設 cake，~1M router 部署

## Limitations / what they don't solve

- CPU overhead 比 fq_codel 略高（hash + multi-tier）
- 對 datacenter 級 (10Gbps+) link 收益遞減
- 不解 endpoint 行為（要 BBR 配合）

## How it informs our protocol design

- G6 server 不必開 cake（DC link buffer 小，fq_codel + BBR 已足）
- **G6 client deployment guide 須建議家用 user 在 router 開 cake**：otherwise 客戶端家用 router bufferbloat 拖累 G6 體驗
- 對「**抗對手做 bandwidth throttle 攻擊**」的場景，cake 在受害者 router 端可緩解

## Open questions

- cake 對 datacenter 工作負載 / 高 link rate 是否 worth deployment 學界尚無共識
- cake + BBRv2/v3 互動 fairness 仍有 open issue
- CAKE 對未來「**ISP 不可預期 buffer**」（5G cellular、衛星 link）的適應性

## References worth following

- bufferbloat.net 全部文章
- OpenWrt SQM-scripts
- Jim Gettys 各年 talk
- Nichols & Jacobson CoDel CACM 2012（前作）
- RFC 8290 fq_codel
