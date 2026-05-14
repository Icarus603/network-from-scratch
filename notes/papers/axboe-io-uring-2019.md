# Efficient IO with io_uring

**Venue / Year**: kernel.dk white paper, 2019  
**Authors**: Jens Axboe  
**Read on**: 2026-05-14（in lesson [2.2 io_uring](../../lessons/part-2-high-perf-io/2.2-io-uring.md)）  
**Status**: full PDF（`assets/papers/kernel-2019-io-uring.pdf`）  
**One-line**: io_uring 設計者親寫的設計總覽 — submission/completion ring + 0-syscall fastpath + registered files/buffers，把 Linux I/O ABI 重寫成 completion-based 模型。

## Problem

Linux 既有 I/O：

- 同步 syscall (`read` / `write`)：每 I/O 1 syscall。1M IOPS 級別 syscall overhead 主導
- POSIX AIO：API 醜、Linux 實作差、隱含 thread pool
- linux-aio (`io_submit`)：只支援 O_DIRECT，且仍要 syscall

需要 **batched + 0-syscall hotpath + 通用 (file/socket/timer)** 的 async I/O ABI。

## Contribution

1. **共享 mmap ring**（SQ + CQ），user/kernel 透過 ring index 通訊，不必 syscall
2. **SQE / CQE 固定大小 entry** (64 / 16 byte)，cache-aligned
3. **IORING_SETUP_SQPOLL**：kernel thread poll SQ，**完全 0 syscall data path**
4. **registered files / buffers**：移除 fdget atomic 與 page pinning per-call cost
5. **opcode 抽象**：read/write/recvmsg/sendmsg/accept/connect/openat/timeout 一個 ring 全收

## Method

- SQ ring：user 寫 tail，kernel 讀 head
- CQ ring：kernel 寫 tail，user 讀 head
- 同步靠 `WRITE_ONCE / READ_ONCE` + memory barrier
- 控制 syscall：`io_uring_setup`、`io_uring_enter`、`io_uring_register`
- 預設模式：user 寫 SQE 後 `io_uring_enter()` 讓 kernel 看
- SQPOLL 模式：kernel 持續 poll，0 syscall

## Results

- 4KB random read 1.7M IOPS/core（vs traditional 370K/core，**4.5×**）
- recvmsg/sendmsg 場景 1.5-2×
- 對 small msg 收益遞減（syscall amortization 主導）

## Limitations / what they don't solve

- API 複雜，user 直接寫易出錯（建議用 liburing）
- Async work 仍走 `io-wq` thread pool（多 thread context switch overhead）
- Many CVEs 2020-2024（多家 cloud disabled by default）
- 對 small msg < 1KB，收益不明顯

## How it informs our protocol design

- G6 server runtime 必須走 io_uring（Rust + monoio / compio）
- 必開：registered files、buffer ring、multishot accept、SEND_ZC for large msg、DEFER_TASKRUN + SINGLE_ISSUER
- Fallback：所有 io_uring path 須有 epoll/kqueue fallback (macOS / restricted Linux)
- Threshold tuning：small msg < 16KB 用普通 send，大 msg 用 SEND_ZC

## Open questions

- io_uring + kTLS clean integration（目前無）
- multi-thread sharing of single ring（DEFER_TASKRUN + SINGLE_ISSUER 限制）
- CVE 模型形式化

## References worth following

- LWN io_uring 系列：https://lwn.net/Kernel/Index/#Block_layer-IO_uring
- Lord of the io_uring：https://unixism.net/loti/
- liburing GitHub
- Didona et al. 2024 *The State of the Art and the Limitations of io_uring* (arXiv)
- monoio architecture：https://github.com/bytedance/monoio
