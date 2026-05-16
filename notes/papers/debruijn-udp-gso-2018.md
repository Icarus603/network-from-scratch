# UDP Generic Segmentation Offload (UDP_SEGMENT)
**Venue / Year**: Linux kernel mainline, kernel 4.18 (2018-08); RFC patchset on netdev mailing list 2018-04
**Authors**: Willem de Bruijn (Google), with Eric Dumazet review
**Read on**: 2026-05-16 (in lesson 2.15)
**Status**: full commit available — `git show bec1f6f697`; LWN write-up at <https://lwn.net/Articles/752184/> (兼 EDT)；patchset 在 lore.kernel.org netdev archive
**One-line**: 賦予 UDP 對等於 TCP TSO 的 software segmentation offload；app 一次送一塊大 buffer，kernel/NIC 按 `gso_size` 切成多個獨立 UDP datagram

## Problem
UDP-based protocols（DNS、QUIC、Google QUIC、RTP、custom 之 game/VoIP transport）在 Linux 上每送一個 datagram 就要進一次 syscall。1 Gbps × 1200B payload ≈ 100k syscalls/sec/core，syscall overhead 把單 core 卡在 ~150 MB/s 以下。TCP 早有 TSO（NIC offload）與 GSO（software fallback）解決這件事，UDP 沒有對應物（UFO 是把單個大 datagram 切成 IP fragments，跨 NAT 災難，被 deprecate）。

## Contribution
1. 引入 `SOL_UDP / UDP_SEGMENT` setsockopt + cmsg ancillary data API，讓 app 顯式指定「請每 gso_size byte 切一個 UDP datagram」。
2. 切出來的是**獨立 UDP datagram**（各自 UDP header、IP header），對中間路由器/NAT/firewall 與 UFO（IP fragments）有本質區別。
3. kernel 端 `udp4_ufo_fragment` / `udp6_ufo_fragment` 做切割，若 NIC 支援 `NETIF_F_GSO_UDP_L4` 則交 NIC（真 USO），否則 kernel 切。
4. 與 hardware checksum offload 協作：要求 hw csum，否則走慢路徑（每 segment 軟體 csum）。

## Method (just enough to reproduce mentally)
- app: `setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso_size, sizeof(u16))` 或每次 sendmsg 帶 cmsg。
- app: `sendmsg(fd, msg, 0)` 其中 msg 可達 64KB-1，最多切出 `UDP_MAX_SEGMENTS = 64` 個 datagram。
- kernel: `udp_sendmsg` → `ip_make_skb` 帶 `gso_size` metadata → 上 qdisc 時 `udp4_ufo_fragment` 切；NIC 支援 USO 則 dev_hard_start_xmit 把 large skb 交 NIC。
- 最後一個 segment 允許小於 gso_size。

## Results
本人 benchmark（Intel Xeon E5, mlx4 NIC, 1500B MTU）：
- baseline sendmsg per datagram: 876 MB/s
- sendmsg + UDP_SEGMENT (gso=1448, 45 segs): 2139 MB/s
- 2.4× throughput / single core
- syscall count: 從 ~900k/sec 降至 ~20k/sec

## Limitations / what they don't solve
- 仍是 single 5-tuple within one sendmsg。跨多個 peer 仍要 sendmmsg。
- 無 hw csum 時降速嚴重。
- max 64 segments × max 1450B MTU ≈ 92KB；要超過得切多次 sendmsg / 用 sendmmsg batch。
- 與 NIC TSO 不同，這是 GSO（software 為主，hw 為輔）；某些低端 NIC 完全不支援 USO，全靠 kernel 切。
- UDP_SEGMENT 不會自動帶 pacing；burst 64 packets 可能 overrun NIC TX ring 或下游 buffer。要配 `SO_TXTIME` + `sch_fq`（EDT model）才能 production 用。

## How it informs our protocol design
- G6 server 為什麼 mandate Linux 5.10+ 的源頭：4.18 GSO，5.0 GRO，5.10 IPv6 對等。
- application-layer record size cap 設為 16×MTU（~19 KB），充分利用 GSO 但留 batching 餘裕。
- pacing 要走 EDT model（見 LWN-752184），不能裸用 GSO burst。
- evaluation harness 必須能切換「GSO on/off」做對照，不然 perf numbers 不可解讀。

## Open questions
- GSO 對「per-packet padding」協議（例如我們可能用 random padding 抗指紋）的相容性：若每 packet padding 長度不同，無法用單一 gso_size 切。是否要設計 "fixed gso_size + intra-packet padding"？
- USO（真 NIC 卸載）在哪些 NIC 上實際工作？mlx5/mlx4 OK，i40e 部分支援，bnxt 較弱。要做 NIC 對比表。

## References worth following
- `Documentation/networking/segmentation-offloads.rst`
- Cloudflare blog: "Accelerating UDP packet transmission for QUIC" (2024)
- de Bruijn talks at netdev / LPC
- 後續 IPv6 對等補丁：`commit 2e8de8576343` (kernel 5.10)
