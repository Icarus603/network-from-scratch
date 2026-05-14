# Kqueue: A Generic and Scalable Event Notification Facility

**Venue / Year**: USENIX ATC 2001  
**Authors**: Jonathan Lemon (FreeBSD)  
**Read on**: 2026-05-14（in lessons [2.1 select→epoll](../../lessons/part-2-high-perf-io/2.1-select-poll-epoll.md) 與 [2.10 macOS](../../lessons/part-2-high-perf-io/2.10-macos.md)）  
**Status**: full PDF（`assets/papers/atc-2001-kqueue.pdf`）  
**One-line**: FreeBSD kqueue 的設計論文 — 用 filter + udata 機制把 fd / signal / process / timer / vnode / user 全部整合在一個 event API，比同期 Linux 早 1 年提出，至今仍是 macOS / FreeBSD 的核心 event mechanism。

## Problem

承 Banga 1999 的 scalable event delivery，需要進一步 **統一各種 event source**：

- 1990s UNIX 對不同 event 用不同 API（`signal()`、`wait4()`、`select()`、`alarm()`、…）
- 每加一種就要新 syscall
- 應用 logic 散在多處 callback

需要 generic、可擴展的 event notification framework。

## Contribution

1. **Filter abstraction**：每種 event source 是個 filter（`EVFILT_READ` / `EVFILT_WRITE` / `EVFILT_SIGNAL` / `EVFILT_TIMER` / `EVFILT_VNODE` / `EVFILT_PROC` / `EVFILT_USER` 等）— 全部統一 API
2. **`udata` 任意 user pointer**：event 觸發時原樣返回，user 可塞 ptr / id 任意 state
3. **`kevent()` 同時改 interest set + 取 ready set**：1 syscall 雙用
4. **Flag-rich semantics**：`EV_ADD / DELETE / ENABLE / DISABLE / ONESHOT / CLEAR / DISPATCH / RECEIPT`
5. **比 Linux epoll 設計更乾淨**：epoll 為達同樣功能要疊 eventfd / signalfd / timerfd / inotify

## Method

- kqueue instance 是 fd
- `kevent()` 一個 syscall：吃 changelist（modify interest set）+ 寫 eventlist（output ready）+ timeout
- 內部用 hash table 維護 (ident, filter) → knote
- 每個 filter 註冊 `f_attach / f_detach / f_event / f_touch` callback

## Results

- 跟 epoll 性能相近（兩者設計收斂）
- 但 API 更統一，跨 event source 都同套 code path
- 影響後續：macOS（直接繼承），Apple iOS / iPadOS

## Limitations / what they don't solve

- 仍是 readiness model（不是 completion）
- 某些 filter 跨 OS 兼容性差（macOS EVFILT_VNODE 有 bug）
- API 雖統一但學習曲線比 epoll 陡

## How it informs our protocol design

- G6 macOS / iOS client 用 kqueue 是必然選擇（透過 GCD `dispatch_source_t` 包一層）
- 統一 event source 設計哲學影響 G6 內部 event loop 抽象（fd / timer / cancel signal 一套 API）
- 對比 epoll 缺陷 → G6 不應假設 epoll 的弱抽象，runtime 抽象層自己統一

## Open questions

- macOS kqueue 跟 FreeBSD kqueue 行為差異（特別是 EVFILT_VNODE、AF_SYSTEM socket）
- kqueue 是否會被 io_uring-like 完成模型在 BSD/Apple 取代（沒看到 Apple 動作）

## References worth following

- macOS XNU `bsd/kern/kern_event.c`
- FreeBSD `sys/kern/kern_event.c`
- libuv / mio 等跨平台 wrap 的 source
- Banga ATC 1999 (前作)
