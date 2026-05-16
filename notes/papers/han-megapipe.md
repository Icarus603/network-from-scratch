# MegaPipe: A New Programming Interface for Scalable Network I/O

**Venue / Year**: USENIX OSDI 2012, pp. 135-148
**Authors**: Sangjin Han, Scott Marshall, Byung-Gon Chun (Yahoo!), Sylvia Ratnasamy (UC Berkeley)
**Read on**: 2026-05-14 (in lesson 1.2)
**Status**: full PDF (14 pages) at `assets/papers/osdi-2012-han-megapipe.pdf` (read pp. 1-10 in detail)
**One-line**: BSD socket API（1983）的根本設計假設（long connections / large messages / single core）跟 2012 datacenter workload（short connections / small messages / many cores）相反；clean-slate 重設計 API（partitioned listener + lwsocket + batching + completion model）對 message-oriented workload 加速 **75% (nginx) – 582% (microbenchmark)**。

## Problem

2012 datacenter workload 跟 1983 socket API 假設**徹底不對齊**：

| Socket API 假設（1983） | Datacenter 現實（2012） |
|---|---|
| Few long-lived connections | Massive short connections (HTTP, RPC, kvstore) |
| Large messages | Small messages (key-value, RPC) |
| Single core | Many cores per server (16+ in 2012) |

導致 4 個 systemic bottleneck：

1. **Accept queue contention**：單一 listening socket 被多核搶；accept() 串行化
2. **Lack of connection affinity**：NIC RSS 把 packet 分到 core A，但 user thread accept() 在 core B → cache bounce on TCB
3. **VFS overhead**：每個 socket 走 VFS path（inode + dentry + file struct）；對 short connection 是純 overhead
4. **System call per I/O**：每 read/write 一次 syscall，不能 batch

Han 在 8-core server 上 microbenchmark：
- **Short connection (1 transaction/connection)** + 8-core → 只 1.3x speedup vs 1-core（嚴重 contention）
- **Long connection (128 transactions/connection)** + 8-core → 6.7x speedup（接近 ideal）
- **Small message (64B)** vs **Large (4KB)**：64B 額外 CPU 81% on per-message overhead

## Contribution

1. **Per-core channel abstraction**：每個 core 一個 bidirectional pipe 給 kernel；request 跟 completion 兩個方向
2. **Partitioned listening socket**：
   - `mp_register()` with `cpu_mask` 把 listening socket 切到指定 core
   - NIC RSS 直接 hash 到對應 core 的 accept queue
   - 完全消除 accept queue contention + cache bouncing
3. **lwsocket（lightweight socket）**：
   - 不走 VFS path（無 inode、無 dentry、無 file struct）
   - 用 channel-local integer ID 代替全局 FD
   - 比 socket() syscall 快 ~3x
   - **代價**：lwsocket 不能跟非 MegaPipe API（e.g. `sendmsg()`）混用；要回 normal FD 需要 fallback function
4. **System call batching**：
   - User library 累積 I/O command，達 threshold（default 32）或 explicit flush 才一次 ioctl
   - Completion event 也 batch 從 kernel 回來
   - 對應 ASYNC IO + IOCP completion model（vs Linux 傳統 epoll readiness model）
5. **Completion notification model**（vs readiness）：
   - epoll 是 readiness model：先告訴 user「fd 可讀了」，user 再 read
   - MegaPipe 是 completion model：user 發 async read，kernel 完成後告訴 user「讀到 N bytes」
   - 後者更適合 batching + transparent async
6. **2200 lines kernel module + 400 lines user library** = full implementation

## Method

### Implementation
- Linux 3.1.3 kernel
- `/dev/megapipe` device + ioctl interface
- 400 lines patch to existing kernel:
  - epoll API exposed to MP-K
  - Multiple sockets listen on same addr:port (cpu_mask)
  - Socket lookup considers cpu_mask
- User library 在 user space，~400 lines

### Application porting
- **memcached 1.4.13**: 9442 LOC, 修改 602 lines (6.4%)
- **nginx 1.0.15**: 86774 LOC, 修改 447 lines (0.5%)
  - nginx 已有 event module abstraction → easy port

### Benchmark
- 8-core Intel Xeon X5560 + 12 GB RAM + Intel 82599 10G NIC
- Linux 3.1.3 + ixgbe 3.8.21
- Microbenchmark (ping-pong RPC) + real workload (nginx HTTP traces, memcached)

## Results

### Microbenchmark
- Short connections (1 transaction): **+582% throughput** vs baseline Linux
- Long connections (128 transactions): **+29% throughput**
- 64B messages: **+82% throughput**
- 4KB messages: **+0% throughput**（系統已飽和 10G NIC）

### Real application
- **memcached**: +15-320% (depending on workload)
- **nginx**: +75% on real HTTP trace replay

### Multi-core scalability
- Baseline Linux short-connection: speedup 1.3 at 8 cores
- MegaPipe short-connection: speedup 6.4 at 8 cores
- **5x better scaling**

### Breakdown (Table 3)
- Partitioning alone (+P): +52.8% short / -50.5% long-conn at 8 cores (long-conn 反而變慢，因 partitioning overhead)
- + Batching: +28-72%
- + lwsocket: +28-580%
- 三者加起來 cumulative

## Limitations / what they don't solve

- **Disk file 沒 lwsocket benefit**——VFS 對 file 是必要的 indirection (path 多 process 共用)
- **lwsocket vs normal FD 不能無痛切**——legacy code 要適配
- **Async API 對 nginx easy（已 abstracted）但對 thread-per-connection server 難移植**
- **MegaPipe 本身不解決 packet rate / NIC 端瓶頸**——只解 socket API 層
- **沒進 mainline Linux**——後來被 io_uring 部分繼承
- **2012 8-core**——現代 64+ core server 上某些 contention 點可能不同
- **TCP 仍在 kernel**——不像 netmap 完全 bypass；對 TCP-heavy workload 是優點，對 raw packet 是限制

## How it informs our protocol design

對 Proteus 設計的**結構性影響**：

### 1. **Proteus server 應該用 completion-based async API**
- io_uring 是 2026 主流——比 epoll/MegaPipe 更通用且 mainline
- Proteus dataplane 應該基於 io_uring 而非 epoll
- 直接收穫 MegaPipe 的 batching benefit

### 2. **Per-core sharding 對 short-connection 場景關鍵**
- 如果 Proteus 走「每 request 一個 short TCP/QUIC connection」（anti-fingerprinting 動機）
- → 必須做 per-core partitioned listener
- → 用 SO_REUSEPORT 在 Linux 上實現（MegaPipe 思想的 mainline 化）

### 3. **Connection affinity**
- 配合 NIC RSS + SO_INCOMING_CPU + thread pinning
- 避免 Proteus connection 跨 core，省 cache bounce
- Phase III 12.4 設計時的 mandatory architectural choice

### 4. **小 message 的開銷需要 batch**
- Proteus 內部 control message 通常小（< 100B）
- 不能每個 message 一次 sendto/recvfrom
- 必須走 io_uring batched submission

### 5. **VFS overhead 對 mobile/edge 場景**
- 嵌入式 / 移動端 Proteus client，每個 TCP connection 的 inode/dentry overhead 累積成問題
- lwsocket 思想對行動端 Proteus 部署有意義（Phase III 12.6 客戶端整合）

## Open questions

- **io_uring 完全取代 MegaPipe 了嗎**？io_uring 是 MegaPipe completion model 的 Linux mainline 版，但 lwsocket 等更 invasive 改動沒進 mainline；長期看 io_uring 是否會繼續演化加上 lwsocket-like fast path？
- **eBPF + socket** 是否能替代 MegaPipe 的核心優化？socket-level eBPF program（cgroup eBPF、sk_msg）可以做 routing 但不 redesign API；兩者 complementary
- **多核 + NUMA 進階優化**：MegaPipe 解單 socket 多 core，但跨 socket NUMA 仍是 open
- **QUIC + completion model**：QUIC 在 user space 跑，傳統用 recvmmsg 收 UDP；用 io_uring 跟 Proteus 整合是否能再 squeeze 出效能？
- **per-flow CPU 隔離 vs anti-fingerprinting**：如果每 flow 跑在固定 core，攻擊者可能用 cache side-channel 區分 flow——是隱私 vs 效能的開放權衡

## References worth following

論文引用中對我們最 relevant：

- **Pesterev et al. 2012** Affinity-Accept (EuroSys 2012) — partitioned listener 同期工作；MegaPipe 引用為 [33]
- **Soares & Stumm 2010** FlexSC — system call batching 同期工作；ref [35]
- **Hruby et al. 2009** Keeping kernel performance from abstractions (HotOS) — VFS overhead 量化
- **POSIX AIO**, **SIGIO** — completion model 的早期 design space
- **Mach Ports** — IPC primitive 可優化 MegaPipe channel
- **kqueue (BSD)** — vs epoll 的 design 比較

延伸（不在 paper 中）：
- **Axboe 2019** io_uring — MegaPipe 哲學的 mainline 化身
- **Marinos 2014** Network Stack Specialization — Sandstorm/Namestorm clean-slate stack
- **Belay 2014** IX (OSDI) — datacenter OS for low latency network IO
- **Rizzo 2012** netmap — 已建檔，正交解法（bypass）
- **Mogul 1997** Receive Livelock — 已建檔，driver-side 部分

## 跨札記連結

- **與 Mogul 1997 Receive Livelock**：Mogul 解 interrupt 層，MegaPipe 解 socket API 層；獨立但 stacking——一個系統可以同時用 NAPI + MegaPipe
- **與 Rizzo 2012 netmap**：哲學差別：netmap = kernel bypass + DIY stack；MegaPipe = keep kernel stack but redesign API。同年（2012）的兩條 high-perf IO 路線
- **與 Crowcroft 1992 Is Layering Harmful**：MegaPipe 直接證實 Crowcroft 的論點——BSD socket 跟 TCP 的 layer interaction 在 multi-core + short-conn 場景下產生 systemic bottleneck
- **與 Saltzer 1984 End-to-End**：MegaPipe 沒違反 e2e，只是讓 e2e 在 kernel 內更快
- **直接 inform** Phase III 12.4 Proteus server 應使用 io_uring + SO_REUSEPORT + per-core affinity
- **直接 inform** Phase III 12.6 客戶端整合（lwsocket 思想對 mobile）
- **直接 inform** Phase III 12.13 高丟包鏈路評測——short-connection 場景的 throughput baseline
