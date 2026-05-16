# The BSD Packet Filter: A New Architecture for User-level Packet Capture

**Venue / Year**: USENIX Winter 1993  
**Authors**: Steven McCanne, Van Jacobson  
**Read on**: 2026-05-14（in lesson [2.5 eBPF 入門](../../lessons/part-2-high-perf-io/2.5-ebpf-intro.md)）  
**Status**: full PDF（`assets/papers/usenix-1993-mccanne-bpf.pdf`），11 頁  
**One-line**: 引入 register-based packet filter VM，為 tcpdump 之祖；30 年後演化成今天的 eBPF，是 Linux kernel 可程式化的學術源頭。

## Problem

1990s 早期 BSD 用 CSPF (CMU/Stanford Packet Filter) 做 user-level packet capture：

- stack-based VM，每 instruction overhead 高
- 對複雜 filter 表達式生成大量 redundant instruction
- 沒 JIT，純解釋

需要 **更快、更簡潔、能 JIT 的 packet filter VM**。

## Contribution

1. **Register-based VM**：2 個 32-bit register（A 累加器、X 索引）+ scratch memory
2. **精簡 instruction set**：~24 opcode，每 instruction fixed-width
3. **CFG-based filter compilation**：filter 表達式 compile 成 DAG，避免 redundant scan
4. **設計 simulation 模型**：證明 BPF 比 CSPF 快 ~20×
5. **可被 JIT**：簡單 ISA，arch-specific code 易生

## Method

- 提供 `bpf_program` UAPI：array of `bpf_insn`
- kernel `bpf_filter()` 跑 VM
- compiler (`libpcap`) 把 BPF assembly / 高層表達式（`tcp port 80`）compile 成 bytecode

## Results

- 比 CSPF 快 20-100× 依 filter 複雜度
- tcpdump 從此走向 mainstream
- 啟動了 30 年的 packet filter VM 演化

## Limitations / what they don't solve

- 2 register 對複雜 filter 不夠用
- 32-bit only
- 沒有 map / state（每 packet 獨立）
- 不能 JIT
- 不能跑「**通用程式**」（限定 filter 語義）

## How it informs our protocol design

- 設計哲學：**「kernel 內運行 user 提交的 small program」是極強的 abstraction**
- 直接 inform 我們的 Proteus 自我量測：用 BPF 在 kernel inline measure 出口流量特徵
- 對手（GFW）的 inspection 工具也是 BPF 演化路徑——理解 BPF 才能 reason about GFW capability

## Open questions（vs 後續演化）

- McCanne 1993 不可能預見：eBPF 200+ helper、map、bounded loop、kfunc、CO-RE、跨 OS portable
- 但**核心架構**（register VM + 靜態驗證 + JIT-friendly）30 年不變

## References worth following

- eBPF / Starovoitov patches 2013-2014 lkml
- Gershuni et al. PLDI 2019（verifier 形式化）
- Vieira et al. CSUR 2020（eBPF + XDP survey）
- Linux Documentation/networking/filter.rst
