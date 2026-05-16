# The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel

**Venue / Year**: ACM CoNEXT 2018, pp. 54-66  
**Authors**: Toke Høiland-Jørgensen, Jesper Dangaard Brouer, Daniel Borkmann, John Fastabend, Tom Herbert, David Ahern, David Miller  
**Read on**: 2026-05-14（in lesson [2.7 XDP](../../lessons/part-2-high-perf-io/2.7-xdp.md)）  
**Status**: full PDF（`assets/papers/conext-2018-xdp.pdf`）+ slides（`conext-2018-xdp-slides.pdf`）  
**One-line**: XDP 把 eBPF program hook 在 NIC driver 收包路徑最早點，達到 24M+ pps/core 的 packet processing，同時保留 Linux kernel 生態的完整兼容性 — 不放棄 stack 又能達 DPDK 級線速。

## Problem

兩條既有路徑都有缺：

- **Linux kernel network stack**：兼容性高，但 per-packet skb alloc + netfilter + 多 hop 開銷，~1-2 Mpps/core 上限
- **DPDK / netmap kernel-bypass**：line rate (~30 Mpps/core)，但**獨佔 NIC**、**失去 kernel stack 整套 feature**（routing, firewall, TCP stack）

需要 **既達 line rate、又保留 kernel 兼容性**的方案。

## Contribution

1. **XDP hook in NIC driver**：packet 還沒進 skb / stack 前跑 eBPF program
2. **Verdict-based**：BPF 程式回 `XDP_DROP / PASS / TX / REDIRECT`
3. **Redirect 機制**：`bpf_redirect_map(devmap | cpumap | xskmap)` 高效轉送
4. **AF_XDP socket**：把 packet redirect 到 user-space mmap ring（zero-copy 替代 DPDK）
5. **三種 mode**：native（driver hook，最快）/ offload（SmartNIC）/ generic（fallback）
6. **完整 benchmark**：證明 24 Mpps drop / 18 Mpps forward / Mellanox ConnectX-5 線速

## Method

- 在 NIC driver NAPI poll loop 內、`netif_receive_skb` 之前 hook
- BPF program 拿 raw frame (DMA page) + minimal metadata (`xdp_md`)
- DROP：page 立刻歸還 driver pool，0 skb alloc
- PASS：照舊 alloc skb + stack
- REDIRECT：用 redirect helper + DPU map 轉送

## Results

| 工作 | XDP | iptables | nftables |
|---|---|---|---|
| Drop | 24M pps/core | 1M pps/core | 1.5M pps/core |
| Forward (route) | 18M pps/core | 1M pps/core | - |

對比 DPDK：差距 < 30%，但**不用獨佔 NIC**。

## Limitations / what they don't solve

- 只有 ingress hook（沒 egress 對應）
- driver 必須 support native XDP（主流 NIC 都有，消費卡某些沒）
- BPF verifier 限制 program 複雜度 - 不能做大型運算 / 加密 / 多 hop algorithm
- packet metadata 受限（沒 conntrack、沒 routing decision）
- 不能直接做 TCP state-aware 操作

## How it informs our protocol design

- **Proteus server 必開 XDP-based DDoS 防線**（SYN flood / rate limit）
- **TC egress + ring buffer** 量 Proteus 自家出口流量特徵，驗證抗指紋
- **AF_XDP 留作 future**：io_uring 已夠，AF_XDP 是極致 mode
- **VPS 部署 guide 須列 supported NIC driver**（virtio-net 5.5+ OK，消費卡某些不行）
- 對手（GFW）能力評估：對手用 XDP 抽特徵 → Proteus 必須對 line rate adversary robust

## Open questions

- XDP egress hook（netdev 提議多年未進主線）
- XDP 階段做加密 / AEAD（verifier 限制現階段不行；future BPF 演化方向）
- XDP + io_uring 整合 API（zero-copy 兩條路重疊）
- XDP failure model：BPF bug 可能卡 NIC 整張卡

## References worth following

- xdp-tools / xdp-tutorial GitHub
- Cilium architecture
- Cloudflare blog: How to drop 10M packets/second
- Facebook Katran source
- Brouer NetDev 各年 talk
