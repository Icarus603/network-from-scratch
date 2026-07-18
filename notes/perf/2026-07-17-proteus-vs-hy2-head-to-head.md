# Proteus β vs Hysteria2: first version-pinned head-to-head

**Date**: 2026-07-17
**Status**: same-host, isolated Linux kernel-netem, burst-loss, and
client-resource evidence; a severe burst cell falsifies universal
performance dominance, and physical cross-host evidence remains pending

## Implementations

Proteus is the current local worktree. Hysteria2 was built directly
from official source commit
`f2ad1de5da52a1da9622285a1d61553ddaa41f21` (2026-07-12), with
binary SHA-256
`d9f6377f74feba03cc056b21165744a764ddfbd1c94a574fbc6f51f59f5b26a8`.
That revision uses apernet/quic-go revision `599b15a1fa26` and
contains the current five-slot Brutal loss-compensation algorithm.

Both implementations used a 1 Gbit/s operator target, a 64 MiB
stream receive window, a 256 MiB connection receive window, and the
same Rust UDP impairment forwarder. The first cells used a 16 MiB
application payload; the steady-state cells used 64 MiB.

## Metric normalization

Proteus sends the selected payload to an echo server and waits for
the same number of bytes to return. Its reported `mib_per_sec` is
therefore:

`payload / (upload time + download time)`.

Hysteria2's official size-based speedtest reports upload and download
separately in decimal MB/s. The comparable round-trip-effective rate
is calculated as:

`payload / (payload / download_rate + payload / upload_rate)`,

then converted from decimal MB/s to MiB/s. This is half the harmonic
mean of the two directional rates. Using either directional Hy2
number directly would overstate Hy2 by roughly 2× against the
round-trip Proteus workload.

## Results

| impairment | Proteus median | Hy2 median normalized | Proteus / Hy2 |
|---|---:|---:|---:|
| 16 MiB, 15% independent loss, 0 ms added delay | 53.08 MiB/s | 42.98 MiB/s | **1.235×** |
| 16 MiB, 15% independent loss, 50 ms one-way delay | 12.00 MiB/s | 9.92 MiB/s | **1.210×** |
| 64 MiB, 0% loss, 50 ms one-way delay | 64.75 MiB/s | 52.53 MiB/s | **1.233×** |
| 64 MiB, 5% independent loss, 50 ms one-way delay | 40.34 MiB/s | 34.16 MiB/s | **1.181×** |
| 64 MiB, 15% independent loss, 50 ms one-way delay | 29.77 MiB/s | 25.43 MiB/s | **1.170×** |
| 64 MiB, 30% independent loss, 50 ms one-way delay | 19.93 MiB/s | 18.49 MiB/s | **1.078×** |

Each cell contains three runs. Forwarder counters measured
the requested loss rate in both directions.

The original 16 MiB sweep had Proteus behind at 5% and 30% loss.
Repeating those cells with a 64 MiB payload reversed both results.
That is evidence that the short-flow result was dominated by
connection startup and run-to-run variance. It is also a warning:
the steady-state controller is now competitive, while short-flow
latency remains a separate optimization target.

## Isolated Linux kernel-netem reproduction

The second experiment replaced the in-process forwarder with three
container roles and two isolated Docker bridges. Client containers
attach only to `10.77.1.0/24`, servers attach only to
`10.77.2.0/24`, and the `netem` router is the sole node on both
networks. Its two egress interfaces each carry a symmetric Linux
`tc netem` qdisc. GRO, GSO, TSO, and UDP segmentation are disabled
at the router to reduce super-packet distortion.

| impairment | Proteus median | Hy2 median normalized | Proteus uplift |
|---|---:|---:|---:|
| 64 MiB, 0% loss, 50 ms one-way delay | 65.24 MiB/s | 51.11 MiB/s | **+27.6%** |
| 64 MiB, 5% independent loss, 50 ms one-way delay | 44.37 MiB/s | 36.05 MiB/s | **+23.1%** |
| 64 MiB, 15% independent loss, 50 ms one-way delay | 32.99 MiB/s | 29.86 MiB/s | **+10.5%** |
| 64 MiB, 30% independent loss, 50 ms one-way delay | 25.69 MiB/s | 18.75 MiB/s | **+37.0%** |

Each cell again contains three runs per implementation. The automatic
validator rejects unequal run counts, traffic that misses either
egress qdisc, and non-zero loss configurations that produce no kernel
drops. The raw qdisc JSON records the configured `loss-random`
probability and counters on both directions.

Do not divide qdisc `drops` by qdisc `packets` and call the result
wire loss. Linux reports skb, segmentation, requeue, and qdisc
counters at different points in the transmit path; even after
offloads are disabled, that ratio is not an unbiased packet-loss
estimator. Here the qdisc option is the configured impairment, while
the non-zero counters prove that both directions exercised it.

## Gilbert-Elliott burst loss and client cost

The runner now starts a fresh client container per observation and
alternates protocol order AB/BA. It records successful attempts,
client cgroup CPU time, process peak RSS, a deterministic 20,000-sample
bootstrap interval for median uplift, an exact two-sided permutation
test, and probability of superiority.

| Gilbert-Elliott cell | Proteus | Hy2 | uplift (95% bootstrap) | p | client CPU | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| P=1%, R=20%, 1-H=50%, 1-K=0%, 50 ms | 51.30 | 43.12 | **+19.0%** (+6.3%, +21.8%) | 0.0035 | 0.564 / 0.644 s | 143.5 / 68.2 MiB |
| P=2%, R=10%, 1-H=75%, 1-K=0.1%, 50 ms | 38.01 | 38.65 | −1.7% (−10.6%, +51.7%) | 0.5163 | 0.646 / 0.736 s | 142.2 / 98.1 MiB |

Every implementation completed seven of seven attempts in both cells.
The first row is evidence of a real Proteus advantage under shorter,
moderate bursts. The second row is a deliberate falsification point:
under longer, stronger bad states, the throughput difference is
statistically unresolved and its median slightly favors Hysteria2.
Proteus consumed less client CPU in both rows but roughly 1.45–2.10×
the peak RSS, consistent with its 64 MiB stream plus 256 MiB connection
window configuration.

## Benchmark-harness defect found and fixed

The first delayed run created one sleeping Tokio task per packet.
Tasks with equal deadlines woke in scheduler order, injecting
unreported packet reordering on top of the requested loss and delay.
That defective run showed Proteus behind Hy2 by roughly 3× and is
excluded.

The forwarder now uses one FIFO deadline queue per direction.
A regression test sends 100 numbered datagrams through the delayed
path and asserts exact receive order. After the fix, Proteus packet
counts returned to the expected range and the 100 ms RTT result
reversed.

## What this proves

In the six controlled same-host cells, all four independent-loss
kernel-netem cells, and the moderate burst-loss cell, Proteus β Brutal exceeds
the current official Hysteria2 Brutal implementation on a normalized
round-trip application workload. The kernel-netem matrix measures
10.5–37.0% uplift and independently reproduces the direction of the
earlier result through an in-path Linux router. The strong burst cell
does not establish either implementation as faster.

## What remains unproven

This is not yet a universal “Proteus is faster than Hy2” result.
The matrix still needs reordering as an explicit independent
dimension, multiple RTTs, server-side CPU and memory measurements,
TUIC-v5 as a second competitor, at least 30 observations in promoted
cells, RSS-window optimization, and a true two-machine run where both
endpoints do not share one OrbStack VM and physical host. The
16 MiB zero-loss, 5%, and 30% exploratory cells were deliberately not
promoted into the headline table because their startup sensitivity
made the curve unstable.

Raw evidence:

- `2026-07-17-brutal-vs-bbr-15pct.jsonl`
- `2026-07-17-proteus-brutal-15pct-100ms.jsonl`
- `2026-07-17-proteus-brutal-64mib-100ms.jsonl`
- `2026-07-17-hy2-f2ad1de-speedtest.jsonl`
- `2026-07-17-kernel-netem-head-to-head.jsonl`
- `2026-07-17-burst-loss-head-to-head.jsonl`

## 2026-07-18 production proxy workload 校正

舊矩陣把 Proteus byte-verified echo 與 Hy2 先 download、後 upload 的
speedtest 正規化後比較，量綱近似，workload 卻不相同，因此降級為
探索證據。新矩陣啟動 codebase 既有的 `proteus-server` 與
`proteus-client` SOCKS5/CONNECT 技術棧，讓 Proteus、Hy2 與
sing-box TUIC-v5 共用同一個 byte-verified SOCKS5 TCP echo driver。

校正先暴露兩個 production 缺陷。啟用非空 `client_allowlist` 時，
server startup self-test 的 ephemeral client 不在 allowlist，健康
key bundle 也會被誤判為 `Closed`；修正後，throwaway context 會
明確安裝 ephemeral identity，並有非空 allowlist 回歸測試。β 的
8 MiB send window 在 100 ms RTT 下又形成約 70 MiB/s 的上限；提升
到與 receive window 相同的 64 MiB 後，64 MiB workload 的 0% loss
debug cell 從落後 Hy2 約 9.3%翻為領先約 14.1%。

100 ms RTT、5% IID loss、64 MiB、7 次時，Proteus 54.27、Hy2
52.36 MiB/s，median +3.65%，但 bootstrap 95% interval 為
-9.92% 到 +10.23%，p=0.594，仍未分出統計優劣。256 MiB 長流、
同 RTT/loss、7 次時，Proteus 87.51、Hy2 85.63 MiB/s，median
+2.20%，interval -0.83% 到 +7.74%，p=0.149。send-window 修正
已把 steady-state 推到略勝，卻尚未達到「超越 Hy2」的證明門檻。

connection lifecycle 反例已在同日修正。production client 現在
以 single-flight pool 跨 SOCKS request 重用已驗證的 β carrier；
每條 stream 仍有獨立 exporter binding、使用者 admission 與 session
semaphore，SIGHUP 只淘汰 idle carrier，既有 stream 可以排空。測試
覆蓋同 carrier 的 sequential／concurrent sessions，以及 production
binary 在多個 SOCKS request 下只建立一條 outer connection。

warm pooled、64 MiB、100 ms RTT、七次矩陣中，0% loss 時
Proteus 95.60、Hy2 80.70 MiB/s，median uplift +18.46%，bootstrap
interval 為正；5% IID loss 時 Proteus 53.83、Hy2 56.14 MiB/s，
median -4.12%，interval 跨越零。後者證明 carrier reuse 消除了反覆
握手的混雜因素，卻也留下真正的 controller gap：Proteus 尚未在
5% loss 超越 Hy2。

這輪同時發現 pooled carrier 把十秒的 dial timeout 錯當成 QUIC
idle timeout，長流會以 `TimedOut` 提前中止。現在 dial deadline
由外層 timeout 單獨約束，negotiated idle timeout 至少六十秒；
修正後兩邊皆完成七次。顯式改寫 Quinn pacer、調 ACK frequency
與 MTU 的實驗都沒有跨過 5% loss 門檻，因此未把無效 pacing fork
留在 repo。

上述 pooled production 矩陣的逐次結果與統計摘要保存在
`2026-07-18-pooled-production-head-to-head.jsonl`。

## 2026-07-18 64 KiB liveness 修正與 30-run 長流晉升

30-run 診斷矩陣揭露一個與 congestion controller 無關的可靠性缺陷：
client 與 server relay 在 application read 恰好填滿 64 KiB buffer 時
跳過 flush，假定後面必有更多資料。request/response workload 若停在
這個整數邊界，兩端會互相等待，最後由 QUIC 60 秒 idle timeout 終止。
`3434b8d` 改為每個完整 logical record 都有 bounded flush，並加入
環境開關式 per-session QUIC counters。修正前 1350 與 1452 MTU
長跑都能復現 `early eof`；修正後下列三格全部 30/30。

| payload | impairment | Proteus | Hy2 | uplift (95% bootstrap) |
|---:|---|---:|---:|---:|
| 64 MiB | 5% IID, 100 ms RTT | 55.41 | 55.77 | −0.64% (−4.92%, +3.32%) |
| 512 MiB | 5% IID, 100 ms RTT | 104.62 | 96.94 | **+7.92%** (**+6.03%, +9.89%**) |
| 512 MiB | 0% loss, 100 ms RTT | 136.54 | 109.72 | **+24.45%** (**+22.88%, +25.62%**) |

三格使用相同 byte-verified SOCKS5 round-trip driver、1 Gbit/s target、
AB/BA 交替順序、64 MiB warmup、1452-byte 已知路徑 MTU，Proteus
commit 固定為 `3434b8d`，Hy2 固定為 `f2ad1de5`。512 MiB 的兩格已
達到至少 30 observations 與正向信賴區間的晉升門檻，證明 Proteus
在這個 same-host Linux netem 拓撲的 sustained bulk workload 超越
Hy2。64 MiB 反例仍然必須並列：短流只證明統計 parity，不能宣稱
Proteus 對所有 workload 都更快。

這仍不是 universal cap。尚缺 Gilbert-Elliott 長流、15%/30% IID、
多 RTT、TUIC-v5、server/client CPU 與 RSS、真正兩機 cross-host。
1452 minimum MTU 也只適用於已量測並完全控制的路徑；未知 Internet、
mobile 或 VPN path 必須保留安全的 1200 fallback。
