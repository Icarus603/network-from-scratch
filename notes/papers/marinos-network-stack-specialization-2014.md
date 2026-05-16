# Network Stack Specialization for Performance

**Venue / Year**: SIGCOMM 2014（pp. 175-186）
**Authors**: Ilias Marinos (Cambridge), Robert N. M. Watson (Cambridge), Mark Handley (UCL)
**Read on**: 2026-05-16（in lesson [[1.18-linux-network-stack]] 引用）
**Status**: 從 SIGCOMM 官方 PDF + abstract + research community 二手分析合成；throughput 數字交叉驗證
**One-line**: 通用 TCP/IP stack 為「同時支援多種應用」付出 10× 性能稅；clean-slate userspace stack（基於 netmap）+ 應用層共享記憶體模型，2014 年就在商用伺服器上做到 10GbE line-rate。

## Problem
- Linux / FreeBSD TCP/IP stack 是「通用大師」——同一支 code 要服務 edge、middlebox、router、container。
- **代價**：傳統 API（socket）+ memory model（per-flow buffer + copy）+ scheduler 互動，使硬體（NIC、CPU、cache）利用率遠低於峰值。
- 2014 年的觀察：大型 service provider 已從「一台 server 多用途」轉向「百萬台專用 server」——對 generality 的需求大幅降低。

## Threat / Performance Model
- 衡量指標：throughput (Gbps)、request rate、CPU utilization、tail latency。
- 對手：not security adversary，是 generic stack 的 abstraction overhead 本身。

## Contribution
1. **Sandstorm**：clean-slate userspace web server，TCP + HTTP + 內容生成全合併在同一 specialized path。
2. **Namestorm**：對應的 DNS authoritative server。
3. 證明：把 application 與 stack 的 memory model 合併、根據 application workload 攤平 protocol cost、緊密綁定 NIC event model、利用 micro-architecture（DDIO、cache topology）→ **2-10× web throughput、9× DNS throughput**、線性 multicore scaling、可飽和 NIC。

## Method
- **基礎**：netmap framework（Rizzo 2012）做 packet I/O，繞過 kernel socket layer。
- **關鍵設計**：
  - 應用 buffer == 網路 buffer（共享，無 copy）
  - TCP 狀態合併到應用 event loop（無 socket abstraction、無 syscall 切換）
  - 對 short flow 攤平 protocol cost：HTTP response packet 在 TCP segment 建立時就**預生成**（pre-computed），不是收到 request 才動態組
  - DDIO（Intel Direct Data I/O）讓 NIC DMA 直接寫 LLC → CPU 不必去主記憶體拿 packet
- **bypass 的 kernel 元件**：socket layer、scheduler、kernel TCP state machine、generic device drivers（用 netmap mode）

## Results
- **Sandstorm vs nginx (FreeBSD)**：2014 商用硬體上 **2-10× throughput**；舊 hw（2006）約 3×；DDIO 讓 cache bandwidth 不再是 bottleneck。
- **Namestorm vs NSD**：DNS RPS **9-13× higher**；FQDN-format hashing 比 wire-format 慢 10-20% 但仍遠勝 NSD。
- **Scaling**：linear multicore（受限於 NIC queue 數）。
- **CPU**：更低（消除 socket → kernel context switch 大量節省）。

## Limitations / what they don't solve
1. **可移植性極差**：clean-slate stack = 重寫所有東西，每個 application 都要 specialization 工程。
2. **協議覆蓋**：只示範 HTTP/1.1 + DNS；TLS、HTTP/2、QUIC 都未支援。
3. **OS 整合**：grep, debugger, packet capture（tcpdump）都不能用——FreeBSD 環境的工程便利性付出代價。
4. **無中介盒場景**：NAT、firewall、IDS 不能直接放這種 stack 後面（沒有標準 syscall trace）。

## How it informs our protocol design
**Proteus server side：直接相關**。
- 我們要設計同時 SOTA 抗審查 + SOTA 速度的協議——server 性能是「速度」的決定性 axis。
- Marinos 證明的核心 lesson：**generic socket stack 是 10× 性能上限的天花板**——若 Proteus 想真正 saturate 商用 NIC（25/100/400 GbE），必須選 kernel-bypass 路線之一。
- 2026 的演化路徑：
  - **AF_XDP**（Linux）：bypass programmable，仍在 kernel control plane 內 → 工程權衡最佳。
  - **DPDK**：商用 SOTA，但需用戶空間整套生態。
  - **io_uring**（[[axboe-io-uring-2019]]）：保留 socket 語意但消除 syscall overhead，對 Proteus protocol（要 TLS / QUIC handshake stack）較友善。
  - **AF_XDP + io_uring + ringbuf**：折衷方案，Cilium / Katran 採用。
- **Forward ref**：Part 12.4 / 12.5 Proteus server 性能評測會回頭引用此 paper 作為 baseline。

## Open questions
- TLS / QUIC handshake CPU cost 是否能被 hardware offload 化（Intel QAT、ARM CCA）→ 結合 specialized stack 達到 line-rate encrypted？
- Stateless processing（QUIC retry token、TLS 1.3 session ticket）能否套用 Marinos 的「pre-computed response」技巧？
- 在 multi-tenant cloud 環境（共享 NIC、SR-IOV、VFIO）能否複製 specialization 收益？

## References worth following
- Rizzo, **netmap** (USENIX ATC 2012) — packet I/O foundation [[rizzo-netmap]]
- Jeong et al., **mTCP** (NSDI 2014) — userspace TCP stack with socket-like API
- Belay et al., **IX** (OSDI 2014) — protected dataplane
- Peter et al., **Arrakis** (OSDI 2014) — OS as control plane
- Axboe, **io_uring** whitepaper (2019) [[axboe-io-uring-2019]]
- Høiland-Jørgensen et al., **XDP** (CoNEXT 2018) [[hoiland-jorgensen-xdp]]
