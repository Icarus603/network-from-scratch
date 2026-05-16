# mTCP: A Highly Scalable User-level TCP Stack for Multicore Systems

**Venue / Year**: USENIX NSDI 2014  
**Authors**: EunYoung Jeong, Shinae Woo, Muhammad Jamshed, Haewon Jeong, Sunghwan Ihm, Dongsu Han, KyoungSoo Park (KAIST)  
**Read on**: 2026-05-14（in lesson [2.9 user-space TCP stack](../../lessons/part-2-high-perf-io/2.9-userspace-tcp.md)）  
**Status**: full PDF（`assets/papers/nsdi-2014-mtcp.pdf`）  
**One-line**: 學術 user-space TCP stack 標竿系統 — 在 share-nothing thread-per-core 模型 + DPDK / netmap 之上重寫 TCP，short-connection scaling 比同期 Linux 快 6×，奠定後續 F-Stack / Seastar 設計。

## Problem

2014 Linux kernel TCP 在 multi-core 上 short-connection scaling 差：

1. 多 thread 共享 `sock` lock、`tcp_hashinfo` 全局 lock
2. file descriptor table 全 process 共享，accept rate 高時瓶頸
3. skb 跨 NUMA cache line bouncing
4. 8-core 機器 short connection ~270K cps，**遠低於 NIC 線速**

## Contribution

1. **完全 user-space TCP**：基於 lwIP 改寫，每 lcore 一套獨立 TCP state
2. **Share-nothing thread-per-core**：每核心自己的 connection hash table、timer wheel、socket namespace
3. **BSD-compatible API**（`mtcp_socket / bind / listen / accept / epoll`）便於 porting
4. **跨 thread 透過 lock-free ring 通訊**（DPDK rte_ring）
5. **RSS hash → lcore binding**：packet 進 NIC RX queue 直接 affinity 對應 lcore，無 cross-core

## Method

- 系統建構在 DPDK / netmap 之上拿 raw packet
- 每 lcore 主迴圈：rx_burst → TCP process → epoll → app callback → tx_burst
- API thread-local，避免 mutex
- 維護自己的 TCP control block table（`tcb`），per-flow

## Results

8-core 機器 vs Linux 同硬體：

| 工作負載 | Linux | mTCP | 提升 |
|---|---|---|---|
| 1KB short connection | 270K cps | 1.7M cps | 6.3× |
| HTTP req/s (Apache bench) | 350K | 1.5M | 4.3× |
| Scaling 1→8 core | sub-linear | near linear | — |

## Limitations / what they don't solve

- TCP 演算法完整度不如 Linux（congestion control 限定 NewReno / CUBIC）
- TCP corner case（PMTUD、retransmit edge）較少測試
- 跟 DPDK 綁定 — 失去 Linux ecosystem
- 2014 後 Linux TCP 改進巨大，差距已縮（2026 Linux 8-core ~1M cps + io_uring）

## How it informs our protocol design

- Proteus **不抄 mTCP 路線**（不重寫 TCP stack），但**吸收 share-nothing thread-per-core 哲學**
- 直接 inform Proteus server 用 monoio / compio + SO_REUSEPORT × N worker + per-worker connection table
- 對「**為何 Linux 對 Proteus 1Gbps 級服務夠用**」的判斷有歷史證據
- Specialization 哲學（Marinos SIGCOMM 2014 配對）：Proteus 是「為 proxy 量身打造的 transport」，跟 mTCP 是 sibling 思路

## Open questions

- 2014 後 Linux TCP scaling 改進到什麼程度？mTCP 數據需要重做
- DPU-resident user-space TCP（BlueField）是 mTCP 下一步
- Specialization for proxy vs Specialization for static HTTP（Sandstorm）取捨

## References worth following

- mTCP GitHub: https://github.com/mtcp-stack/mtcp
- F-Stack: FreeBSD TCP + DPDK
- Seastar (ScyllaDB)
- Marinos SIGCOMM 2014 *Network Stack Specialization*
- Han et al. MegaPipe OSDI 2012
