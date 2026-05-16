# netmap: A Novel Framework for Fast Packet I/O

**Venue / Year**: USENIX Annual Technical Conference 2012
**Authors**: Luigi Rizzo (Università di Pisa, Italy)
**Read on**: 2026-05-14 (in lesson 1.2)
**Status**: full PDF (12 pages) at `assets/papers/usenix-atc-2012-rizzo-netmap.pdf`
**One-line**: 用 **memory-mapped shared region + pre-allocated buffer + batched syscall** 三招同時解決 BSD socket 的三大 packet IO overhead；900 MHz 單 core 達到 14.88 Mpps（10G line rate at 64B），**比標準 socket API 快 20x**。

## Problem

2012 年 1-10 Gbps NIC 已普及，但 OS socket API 跑不動 line rate。BSD sendto/recvfrom 對 1500B packet 才能維持線速；64B packet 連 1 Gbps 都吃力。

FreeBSD sendto() 一次調用花 ~950 ns（論文 Fig 2 細拆）：
- 8 ns: userspace 設好參數
- 104 ns: syscall entry
- 137 ns: socket layer + mbuf allocation
- 198 ns: ip_output (route lookup, header setup)
- 220 ns: ether_output_frame + driver
- 162 ns: NIC programming + mbuf mangling

→ 10G line rate 需要 670k pps（1500B）或 14.88M pps（64B），950 ns/packet 只有 ~1M pps，**差 14 倍**。

## Contribution

1. **三大瓶頸 identification + simultaneous fix**：

   | 瓶頸 | 來源 | netmap 解法 |
   |---|---|---|
   | Per-packet dynamic alloc | sk_buff/mbuf alloc/free per packet | **Pre-allocated fixed-size buffer pool** |
   | System call cost | 1 syscall per packet | **Batched syscall** (1 ioctl handles N packets) |
   | Data copies | kernel-userland memcpy | **Memory-mapped shared region** (zero-copy) |

2. **Lightweight data model**：
   - Each NIC 暴露 `netmap_ring`（device-independent copy of NIC ring）
   - User 跟 kernel 共享同一塊 mmap'd region
   - Buffers fixed-size (2KB)，由 kernel preallocate，user 用 index 引用
3. **Safe**：netmap clients 不能 crash kernel——device register 仍由 kernel 保護，buffer length/index 都由 kernel 驗證
4. **Standard primitives**：用 `select()/poll()` 做 event notification（不像 PSIOE/PF_RING 用 custom ioctl）——容易整合到既有 event loop
5. **Multi-queue support**：每個 thread bind 到一個 NIC queue + 一個 CPU core
6. **Zero-copy forwarding between interfaces**：兩個 NIC ring 在同一塊 shared memory，forwarding 只需要交換 buffer index
7. **libpcap compatibility shim**：~20 行 wrapper 讓既有 libpcap-based app（OpenvSwitch、Click、Snort）直接享受 netmap 速度

## Method

### Architecture
- Linux + FreeBSD 雙平台實作
- ~2000 行 system call + driver support
- 200 行 C header 給 client
- 每個 NIC driver 改 ~500 行
- 支援 Intel 10G ixgbe、various 1G adapter

### Evaluation setup
- Intel i7-870 4-core @ 2.93GHz + Intel 82599 10G NIC
- Can clock down to 150 MHz to find CPU bottleneck
- 跑 packet generator / receiver / forwarder / Click / OpenvSwitch

### Comparison baselines
- FreeBSD netsend (userspace + raw socket): ~1.05 Mpps
- Linux pktgen (in-kernel): ~4 Mpps
- netmap: 14.88 Mpps with 1 core @ 900 MHz

## Results

### Throughput
- **14.88 Mpps (10G line rate at 64B) with 1 core @ 900 MHz** = 60-65 cycles/packet
- Linear scaling with cores
- 64B sweet spot；65-127B 有 cache-line 對齊問題，receive 降到 7.5 Mpps
- Batching effect: batch=1 → 2.45 Mpps；batch=8 → line rate

### Forwarding performance（更貼近 real-world）
| Configuration | Mpps |
|---|---|
| netmap-fwd zero-copy | 14.88 (line rate) |
| netmap-fwd + libpcap shim | 7.50 |
| Click + netmap | 3.95 |
| Click + native libpcap | 0.49 |
| OpenvSwitch + netmap | 3.00 |
| OpenvSwitch + native libpcap | 0.78 |

**用 libpcap shim 套既有 application 直接得到 4-8x 加速**——這是 netmap 的真實工程價值。

## Limitations / what they don't solve

- **TCP/IP stack 完全 bypass**——netmap 給 raw packet，不替你做 TCP；要 TCP 得自己實作或 stack-on-netmap（後來 Yasukata 2016 StackMap 補上）
- **Driver modifications required**——每個 NIC 要改 ~500 行 driver code；不是所有 NIC 支援
- **Safety vs performance trade-off**：論文 §4.4 提到「multiple processes 共用 memory region 仍可干擾彼此」——只有 hardware multi-queue 才能完美隔離
- **No flow steering**——netmap 把 packet 整 ring 給 user，不像 Flow Director 能 per-flow 分到不同 ring
- **2012 主流 1-10 Gbps**——40/100 Gbps 沒測試（後續 Neugebauer 2018 揭露這層有新 bottleneck）
- **vs DPDK**：DPDK 走更激進 path（直接 PMD，不用 select/poll），最終勝在 raw throughput；netmap 勝在 portability + standard syscall

## How it informs our protocol design

對 Proteus 設計的**重要選項**：

### 1. **如果 Proteus 走 kernel-bypass 路線**
- netmap 是 baseline candidate（簡單、open source、kernel mainstream）
- DPDK 是更激進選項（throughput 更高但工程量大）
- **AF_XDP（Linux 內建）是 2026 的中道選擇**——繼承 netmap zero-copy + 整合 NAPI
- **Proteus Phase III 12.4 應該 benchmark 三條路線**

### 2. **batched syscall 是核心優化**
- 即使不走 zero-copy，**batching** 本身就值幾倍加速
- io_uring 就是這個思想的 modern 化
- Proteus 應該所有 syscall 都用 batched API（sendmmsg / recvmmsg / io_uring）

### 3. **libpcap shim 啟示**
- Phase III deployment 時，Proteus 可以提供「libpcap-compatible」shim 讓 evaluation tool（Wireshark、Zeek、Suricata）無痛接上
- 這是 12.15 抗審查評測的 win-win 設計

### 4. **2KB buffer 設計選擇**
- netmap 固定 2KB——對 MTU 1500 留 ~500 byte 給 metadata
- Proteus 內部 buffer 設計可以參考——對齊 MTU 而非 PAGE_SIZE

### 5. **針對 GFW 的 packet generator**
- Phase III 9.12 主動探測模擬可以基於 netmap 寫——能達 line rate 的 active prober
- 對手是否能達 line rate prober 是我們協議要設想的場景

## Open questions

- **netmap 在 40/100 Gbps NIC 上 still relevant**？Neugebauer 2018 揭露 PCIe 變成 bottleneck，netmap 設計不解決這層；可能需要 DPDK + DDIO 才能跑滿
- **vs AF_XDP**：兩者都是 zero-copy；AF_XDP 在 Linux mainline，netmap 更跨平台；長期 winner 不明
- **NUMA-aware netmap**？多 socket 系統下 netmap ring 跨 NUMA 會掉 5-10% throughput；論文沒處理
- **SmartNIC 卸載**：如果 NIC 內就能跑 ML inference 識別 Proteus packet，netmap 級的 host-side throughput 還重要嗎？
- **零拷貝 + TLS**：netmap 給 plaintext packet，TLS 加密必須 copy（需要 crypto 處理）——這跟 zero-copy 哲學矛盾，kTLS 是嘗試解法

## References worth following

論文引用中對我們最 relevant：

- **Mogul & Ramakrishnan 1997** Receive Livelock — 已建檔，netmap 繼承其 polling 思想
- **Kohler et al. 2000** Click Modular Router — 已建檔，paper §3.1 把 Click 包成 netmap client
- **Dobrescu et al. SOSP 2009** RouteBricks — 多核 software router，netmap 的前驅
- **Han et al. SIGCOMM 2010** PacketShader — GPU-based packet processing
- **Intel DPDK** ref [8] — 商業競品
- **McCanne & Jacobson 1993** BSD Packet Filter — BPF，netmap 的 ancestral 工具
- **Smith & Traw 1993** Giving Applications Access to Gbps Networking — userspace networking 早期工作

延伸：
- **Rizzo, Carbone, Catalli INFOCOM 2012** Transparent acceleration of software packet forwarding — 同作者 follow-up
- **Yasukata et al. ATC 2016** StackMap — netmap + TCP/IP stack
- **Høiland-Jørgensen et al. CoNEXT 2018** XDP — AF_XDP 設計（netmap 哲學的 Linux mainline 版）
- **Axboe 2019** io_uring whitepaper — 通用版的 batched async syscall

## 跨札記連結

- **與 Mogul 1997**：Mogul 解 interrupt overhead；netmap 接著解剩下三個 overhead（alloc、syscall、copy）；兩者組合就是 modern packet IO 的全套
- **與 Crowcroft 1992 Is Layering Harmful**：netmap 直接證實 Crowcroft 警告——standard socket API 的 layer interaction 慢 20x；netmap 用更平的設計打贏
- **與 Click 2000**：netmap §5.6 把 Click userspace 用 netmap 加速 4 倍；證明 element-based architecture + zero-copy 可組合
- **與 Han 2012 MegaPipe**：兩個獨立攻擊不同層——netmap bypass kernel stack，MegaPipe redesign socket API
- **與 Neugebauer 2018 PCIe**：netmap 解 host-side overhead；6 年後 Neugebauer 揭露 PCIe 才是新 bottleneck
- **直接 inform** Phase III 12.4 Proteus 資料路徑選擇（io_uring vs AF_XDP vs DPDK 的決策架構）
- **直接 inform** Phase III 12.15 評測平台（用 netmap-based fast prober）
