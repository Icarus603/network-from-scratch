# Understanding PCIe Performance for End Host Networking

**Venue / Year**: ACM SIGCOMM 2018, Budapest, August 2018, pp. 327-341
**Authors**: Rolf Neugebauer, Gianni Antichi (Queen Mary, U of London), José Fernando Zazo (Naudit HPCN), Yury Audzevich (U of Cambridge), Sergio López-Buedo (U Autónoma de Madrid), Andrew W. Moore (U of Cambridge)
**Read on**: 2026-05-14 (in lesson 1.2)
**Status**: full PDF (15 pages) at `assets/papers/sigcomm-2018-neugebauer-pcie.pdf` (read pp. 1-10 in detail)
**One-line**: 40/100 Gbps NIC 時代，**PCIe bus 本身**而非 NIC 或 software 成為新瓶頸；建立 PCIe 性能 model + open-source pcie-bench 工具量化 DMA latency/bandwidth，發現 **PCIe Gen3 x8 對 64B packet 只剩 ~10 Gbps 可用頻寬**（vs 物理層 62.96 Gbps）。

## Problem

2018 主流 NIC 進到 40/100 Gbps，host-side packet 處理 frameworks（DPDK、netmap、AF_XDP）已 squeeze 完 software overhead。但**新的瓶頸出現**：PCIe bus 本身。

PCIe 過去**沒人嚴肅研究**——「PCIe 是 fast interconnect，當作 free 用」是普遍假設。Neugebauer 想：**這假設在 40/100 Gbps 下還成立嗎**？特別當 NIC 也是 programmable / SmartNIC 時，理解 PCIe 變成必要。

## Contribution

1. **First public detailed PCIe performance characterization**：
   - PCIe Gen3 x8 physical: 62.96 Gbps
   - 扣 DLL framing (~10%): 57.88 Gbps
   - 扣 TLP overhead (depends on transfer size): **64B packet 只剩 ~10 Gbps**，1500B packet 剩 ~50 Gbps
   - "Saw-tooth pattern": packet size 跨 cache line / TLP boundary 時 throughput 跳變
2. **`pcie-bench` 工具套件**：
   - 開源 (<https://www.pcie-bench.org>)
   - 兩個獨立實作：商用 Netronome NFP NIC + 學術 NetFPGA-SUME
   - 系統性量化 DMA latency / bandwidth / NUMA effects / DDIO impact
3. **NIC PCIe latency 數據**：
   - 64B DMA read round-trip: ~547 ns（NFP-6000）/ ~550 ns（NetFPGA）
   - PCIe 貢獻 ~90.6% latency（其他是 NIC 內部處理）
   - Variance: 95th percentile 接近 median 但 99.9th percentile 可達 ms 級
4. **DDIO (Data Direct I/O) 量化**：
   - Intel 自 Xeon 開始 PCIe write 直接寫 LLC
   - cold cache 時 LAT_WRRD 多 ~70 ns（needs LLC eviction）
   - DDIO 只占 LLC 10%，超過會強制 main memory write
5. **NUMA impact**：
   - PCIe device attached 在 socket 0 + buffer in socket 1 → **20% throughput drop**（64B reads）
   - PCIe Gen3 + 跨 NUMA = packet rate 上限被砍 1/5
6. **PCIe root complex 跨世代差異**：
   - Xeon E5 (Sandy Bridge → Broadwell) vs Xeon E3 (Haswell desktop chipset)
   - 同代 CPU 但不同 PCIe root complex implementation latency 差 2-5x
   - 99.9th percentile latency 從 1.2 μs 到 5.7 ms（巨大）
7. **Practical recommendations**：
   - NIC software 必須能處理 30+ in-flight DMA
   - Driver 必須 batch descriptor
   - DDIO 對 small packet 有用，對 large packet (>512B) 無感

## Method

### PCIe model
- Bandwidth: B = ⌈sz/MPS⌉ × MWr_Hdr + sz（MWr = Memory Write TLP）
- Latency: 由 PCIe Gen + lane count + root complex implementation 決定
- 用 lspci 配合 cache-controlled microbenchmark 量化

### `pcie-bench` 實作
- **Netronome NFP-6000/4000** 商用 SmartNIC：1200 lines Micro-C
- **NetFPGA-SUME** 學術可重編程 NIC：1500 lines Verilog/SystemVerilog
- 兩個獨立實作互相驗證 model

### Test platforms
- 7 個不同代 Xeon platform (Sandy Bridge → Broadwell)
- 同 NIC、不同 CPU/chipset
- 控制 cache state (cold / host-warm / device-warm)
- 控制 NUMA placement (local / remote)

## Results

### Saw-tooth bandwidth pattern (Figure 1)
- "Effective PCIe BW" curve has visible saw-tooth at TLP boundaries
- Simple NIC (no batching) reaches 40 Gbps only at packet size ≥ 512B
- Modern NIC with kernel driver: ~45 Gbps for ≥ 256B
- DPDK driver: ~50 Gbps for ≥ 256B
- 64B packet: 即使 DPDK driver 也只 ~10 Gbps

### Latency by transfer size
- 8B DMA read: ~520 ns
- 64B: ~547 ns
- 128B: ~1000 ns
- 1500B: ~2400 ns (linear after small packet floor)
- PCIe contribution: 90% (small) → 77% (large)

### DDIO benefit
- 64B random reads with cold cache: ~32 Gbps
- 64B random reads with warm cache (DDIO): ~50 Gbps
- 大 packet (>512B) DDIO 沒影響

### Inter-CPU variance
- Xeon E5-2630 v4 (Broadwell): clean latency distribution，99.9th = 947 ns
- Xeon E5-2620 v2 (Ivy Bridge): bimodal latency，99.9th = 11987 ns
- Xeon E3-1226 v3 (Haswell desktop): 99th = 5707 ns，99.9th = 5.8 ms

→ **same generation, different root complex = orders of magnitude latency variance**

## Limitations / what they don't solve

- **單向 measurements**——DMA write latency 無法直接測（writes are posted），只能 indirectly
- **2018 cutoff**——PCIe Gen4 (2017+ 部分) / Gen5 (2022+) 未涵蓋；Gen5 doubles bandwidth 應該緩解
- **沒涵蓋 GPU-direct / RDMA paths**
- **NetFPGA-SUME 跟 NFP-6000 不能 represent all 商用 NIC**——Mellanox / Broadcom / Marvell 可能不同
- **沒處理 IOMMU 細節**——只說 IOMMU miss 很貴，沒量化各種 IOMMU configurations
- **CXL not yet**——CXL coherent fabric (2022+) 改寫 host-device 互動 model

## How it informs our protocol design

對 G6 的**deployment & evaluation 層級**影響：

### 1. **Phase III 12.11 baseline 必須記錄 PCIe / NUMA topology**
- 只記 "10G NIC" 不夠
- 要記 PCIe Gen + lane count + 配置在哪個 socket + buffer 在哪個 socket
- 否則 reproduce 不出來

### 2. **Server hardware selection 是 evaluation 一部分**
- G6 server 跑同一份 binary 在不同 Xeon 上 throughput 可能差 2-5x
- Phase III 12.18 真實對抗測試的境內 VPS 要記錄 CPU 型號

### 3. **Single-instance 5 Gbps 在 PCIe Gen3 x8 上**
- 1500B packet @ 5 Gbps ≈ 416 Kpps，PCIe Gen3 x8 沒問題
- 64B packet @ 5 Gbps ≈ 9.7 Mpps，**這超過 PCIe Gen3 x8 64B 可用頻寬 10 Gbps 對應的理論上限**
- → G6 small packet 場景如果要達 5 Gbps line rate，**需要 PCIe Gen4 或更新**

### 4. **NUMA 強制注意**
- VPS 上跑 G6，process 必須 pin 到 NIC attached socket
- `numactl --cpunodebind=0 --membind=0 ./g6-server` 是 baseline 啟動命令
- 否則白白損失 5-20% throughput

### 5. **不要假設 packet rate 限制**
- 對手（GFW）也受 PCIe 限制——他們也跑在 PCIe NIC 上
- 如果我們協議 packet rate 高過 PCIe Gen3 x8 限制，GFW middlebox 可能 drop（false negative）或被迫 sample
- → packet rate 可能成為 anti-fingerprinting 維度

### 6. **CXL / PCIe Gen5 是 5 年 deployment 變數**
- G6 spec 應該 future-proof：不假設 packet/buffer 一定能 fit in PCIe DMA
- Spec 設計時保留「per-flow buffer size 可調」的 knob

## Open questions

- **PCIe Gen5 + CXL 下 PCIe 還是 bottleneck 嗎**？Gen5 是 Gen3 的 4x；CXL allows coherent shared cache 跟 NIC——這兩個會徹底改變 host-NIC 互動 model
- **SmartNIC FPGA 內部 PCIe** vs **host PCIe**：programmable NIC 內部也有 PCIe（chiplet level）；論文沒分析這層
- **AI accelerator interconnect**：GPU/TPU via NVLink / TPU mesh 跟 PCIe 哪邊更貼近 G6 服務端架構？
- **多 PCIe device 競爭**：G6 server 同時有 NIC + NVMe SSD + GPU，PCIe root complex 怎麼分配 bandwidth？
- **PCIe security**：DMA attack（Thunderclap 2019 等）—— PCIe 信任 model 對 G6 server hardening 有意義嗎？

## References worth following

論文引用中對我們最 relevant：

- **Intel DDIO whitepaper** ref [20] — Direct I/O 機制 spec
- **PCI-SIG specification** ref [47][57] — PCIe spec
- **Mellanox ConnectX programmer's guide** — modern NIC reference
- **Yasukata et al. 2016 StackMap** — netmap-based fast stack
- **Mansfield-Devine 2019 (PCIe attacks via Thunderbolt)** — security implications

延伸（不在 paper 中）：
- **Han et al. 2010 PacketShader** — GPU NIC offload
- **Belay 2014 IX (OSDI)** — datacenter OS
- **AF_XDP papers** — Linux mainline 對 PCIe-aware 設計
- **CXL specifications 2.0/3.0** — 後 PCIe 互連
- **NVIDIA BlueField DPU** — SmartNIC 商用 reference

## 跨札記連結

- **與 Mogul 1997**：Mogul 解 CPU interrupt 層 bottleneck；Rizzo 解 software stack；Neugebauer 揭露 hardware 層 PCIe 才是新瓶頸——三篇形成 packet-processing cost 階梯
- **與 Rizzo 2012 netmap**：netmap 假設 PCIe is fast；Neugebauer 證明在 40+ Gbps 下這假設崩潰
- **與 Han 2012 MegaPipe**：MegaPipe 解 socket API；Neugebauer 解硬體互連——兩層獨立 bottleneck 都要處理
- **與 Saltzer 1984 End-to-End**：PCIe 是 host 內部 e2e 路徑的一段——middle box (PCIe root complex) 都會引入 latency variance
- **直接 inform** Phase III 12.11 baseline evaluation 必須記錄 PCIe + NUMA topology
- **直接 inform** Phase III 12.4 G6 server CPU pinning + NUMA-aware deployment
- **直接 inform** Phase III 12.18 真實對抗測試 hardware reporting standards
