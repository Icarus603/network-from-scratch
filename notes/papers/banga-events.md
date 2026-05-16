# A Scalable and Explicit Event Delivery Mechanism for UNIX

**Venue / Year**: USENIX Annual Technical Conference 1999  
**Authors**: Gaurav Banga, Jeffrey C. Mogul, Peter Druschel  
**Read on**: 2026-05-14（in lesson [2.1 select→epoll](../../lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)）  
**Status**: full PDF（`assets/papers/atc-1999-banga-events.pdf`）  
**One-line**: 史上第一篇明確指出 `select()` O(N) 病灶並提出 explicit event delivery 設計的論文 — epoll / kqueue / IOCP 的學術源頭。

## Problem

1990s 末 web server（Apache、Squid）已遇 C10K：

- 數千 fd 同時等的場景
- `select()` 每 syscall 必過 O(N) scan，user/kernel 雙端
- `poll()` 改 bitmap 為 array，**O(N) 病灶不變**

需要 scalable I/O readiness notification API。

## Contribution

兩個 idea 影響後續所有 I/O 多工 API：

1. **Interest set 與 ready set 分離**：
   - select/poll 每 syscall 重傳整個 interest set（O(N)）
   - 正確設計：interest set 是 **kernel-side persistent state**，user 只增量 add/remove
   - ready set 只有「新事件」，size O(R)，R = 真實 ready 數
2. **Explicit event delivery**：
   - 不重複通知「fd 仍 readable」，只通知「狀態變化」
   - 對應後來 epoll ET / kqueue EV_CLEAR

提出 prototype `/dev/poll`（Solaris）後續 epoll / kqueue 都繼承這兩個 idea。

## Method

- 設計 declarative event API
- 把 interest set 維護在 kernel
- Wait queue + callback 機制：每 fd 變化時 kernel 主動 push 進 ready set
- syscall 成本 O(R)（return ready 數）

## Results

對比 select / poll：

- 10K fd 場景 syscall 開銷下降 ~10×
- 加 fd / 移除 fd 是 O(1)
- 對大 fd 集合 + 少 active 比例的 workload，達到 expected complexity

## Limitations / what they don't solve

- 仍是 readiness model（不是 completion model，1999 還沒看到）
- API 細節 — 後續 epoll / kqueue / IOCP 各做了自己的設計
- 沒解 thundering herd / fairness

## How it informs our protocol design

- 直接 inform Proteus server epoll(ET) 配 SO_REUSEPORT 的 architecture
- 「**interest set persistent、ready set incremental**」是 Proteus 內部 connection table 設計的心智模型
- 對比 readiness 跟 completion 模型（io_uring）的差異，是評估 Proteus server stack 的根本框架

## Open questions

- Fairness in epoll (本論文沒解)
- io_uring 完全取代 epoll 是否可行（2024 LWN 仍討論）
- eBPF 程式化 ready list 處理（未實現）

## References worth following

- Lemon ATC 2001 kqueue paper
- Provos & Lever ATC 2000 `/dev/epoll`
- Libenzi 2001-2003 lkml epoll patches
- Pariag EuroSys 2007 server architecture comparison
