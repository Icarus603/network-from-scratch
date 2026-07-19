# Proteus β vs Hysteria2: first version-pinned head-to-head

**Date**: 2026-07-17
**Status**: same-host, isolated Linux kernel-netem, burst-loss, and
client-resource evidence; 512 MiB sustained bulk wins promoted IID and
severe-burst cells, and authenticated adaptive recovery now wins one
promoted 64 MiB severe-reordering cell. Broader reordering and physical
cross-host dominance remain unproven.

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

這仍不是 universal cap。尚缺 15%/30% IID 長流、多 RTT、TUIC-v5、
server/client CPU 與 RSS、真正兩機 cross-host。
1452 minimum MTU 也只適用於已量測並完全控制的路徑；未知 Internet、
mobile 或 VPN path 必須保留安全的 1200 fallback。

## 2026-07-18 Gilbert-Elliott 長流晉升

相同 production SOCKS5 路徑再加入兩種 Gilbert-Elliott burst cell。
512 MiB、100 ms RTT、64 MiB warmup 與固定 1452 MTU 均保持不變。

| burst cell | runs | Proteus | Hy2 | uplift (95% bootstrap) |
|---|---:|---:|---:|---:|
| P=1%, R=20%, 1-H=50%, 1-K=0% | 7 | 116.20 | 103.65 | **+12.11%** (**+9.65%, +15.86%**) |
| P=2%, R=10%, 1-H=75%, 1-K=0.1% | 30 | 91.57 | 86.31 | **+6.09%** (**+3.90%, +8.59%**) |

兩邊在 moderate cell 都是 7/7，在 severe cell 都是 30/30。第一次
severe 30-run 嘗試於第 3 對揭露 benchmark client 的十秒
`beta_first_timeout_secs` 會在長 bad-state 中觸發 β→α fallback，
因此整輪拒收。`0954eeb` 把 benchmark timeout 顯式化為 60 秒、
寫入 metadata，並把任何 α fallback 升格為 cell failure。重跑日誌
的 fallback count 為零，故表內 severe 結果是純 β 對 Hy2。

這組 512 MiB 結果推翻了「severe burst 必然落後」的猜想，卻沒有
抹去前述 64 MiB severe-burst 反例：短流當時為 −1.7%，信賴區間
跨零。現有證據支持 sustained-bulk burst superiority，仍不支持
所有 payload、RTT 與路徑上的 universal dominance。

## 2026-07-18 official TUIC-v5 初篩

第一次 `INCLUDE_TUIC=1` 矩陣錯用了 sing-box 1.13.12 相容實作；
它在 0% loss、100 ms RTT 仍只有 9.59 MiB/s，證明預設 QUIC
flow-control window 污染比較，因此兩個 sing-box cell 全部拒收。
runner `cfc8ab9` 改回 codebase 已有的 upstream TUIC v5 1.0.0
client/server，兩端顯式使用 64 MiB send/receive window，並保存
官方 client/server daemon logs 與 image digest。

| impairment | Proteus | Hy2 | official TUIC v5 | Proteus vs TUIC (95% bootstrap) |
|---|---:|---:|---:|---:|
| 0% loss, 100 ms RTT | 139.16 | 110.37 | 68.58 | **+102.92%** (**+82.69%, +114.52%**) |
| 5% IID, 100 ms RTT | 104.94 | 96.12 | 73.57 | **+42.63%** (**+37.46%, +51.54%**) |

三方在初篩兩格都是 7/7，沒有 α fallback 或 run failure。5% IID
cell 隨後從乾淨的 `519bd6d` 晉升到 30 observations：Proteus
105.32、Hy2 96.92、official TUIC 70.75 MiB/s，三方皆 30/30。
Proteus 對 TUIC uplift 為 **+48.86%**，bootstrap 95% interval
**+40.82% 到 +52.85%**；對 Hy2 則為 **+8.66%**，interval
**+4.94% 到 +11.08%**。這證明 5% IID sustained-bulk cell 同時
超越兩個 version-pinned 對手。0% TUIC cell 仍只有七次，短流、多
RTT 與 cross-host 仍不得外推。

## 2026-07-18 AES v1.1 與 allocator/RSS 校正

authenticated AEAD agility 把 inner DATA/CLOSE/RATCHET 從固定
ChaCha20-Poly1305 升級為 transcript-bound negotiation；v1.1 client
offer、server selection、identity signature、HMAC 與 Finished 均涵蓋
suite，server 在雙方支援時選擇 AWS-LC AES-256-GCM。相同 64 KiB
microbenchmark 中，硬體 AES seal/open 約 7.98/8.11 GiB/s，
ChaCha20-Poly1305 約 628 MiB/s。這只證明 primitive headroom；
production proxy 數據才是協議層判準。

512 MiB、5% IID loss、100 ms RTT、64 MiB warmup、固定 1452 MTU、
64/256/64 MiB QUIC window 與 1 Gbit/s target 的七輪 matched cell
得到以下結果：

| implementation | throughput median | client CPU median | post-run RSS median |
|---|---:|---:|---:|
| Proteus β + AES v1.1 + mimalloc purge=0 | **129.88 MiB/s** | **2.542 s** | **31.27 MiB** |
| Hysteria2 `f2ad1de5` | 95.53 MiB/s | 2.583 s | 175.91 MiB |

Proteus throughput uplift 是 **+35.97%**，20,000-resample bootstrap
95% interval 為 **+30.08% 到 +38.36%**，exact two-sided permutation
`p=0.00058275`，probability of superiority 為 1.0，兩邊皆 7/7
成功。Proteus 每輪 RSS 為 33.14、35.48、28.56、29.31、29.91、
31.27、32.10 MiB，沒有持續爬升。

診斷 A/B 也保留失敗邊界。glibc allocator 的同條件舊 cell 在七輪後
post-run RSS median 約 263.86 MiB；mimalloc 使用 v3 預設 1000 ms
非同步 purge 時，頁面會在約 46–194 MiB 間依採樣時點擺動，median
仍為 182.99 MiB。設定官方 `MIMALLOC_PURGE_DELAY=0` 後，free page
在觀測前歸還 OS，吞吐優勢沒有消失，RSS 才穩定落到 28.56–35.48
MiB。這支持 allocator high-water diagnosis，並反駁「QUIC payload
buffer 永久洩漏」假說。

原始逐輪 throughput、CPU、RSS、image digest、commit、qdisc drop
counter 與完整環境 metadata 保存在
`2026-07-18-mimalloc-aes-v11-head-to-head.jsonl`。這仍是單一
same-host Linux/OrbStack、單一 IID cell；它證明該 cell 同時勝過
Hy2 的 throughput、CPU 與 RSS，不能代替多 RTT、burst matrix、
physical dual-host 與 short-flow 證據。

## 2026-07-18 AES/mimalloc 擴展矩陣

`16fdf2f` 的乾淨 worktree 與同一組 version-pinned image 再覆蓋
0/15/30% IID、兩種 Gilbert-Elliott burst、20/300 ms RTT，以及
1200-byte QUIC minimum MTU。所有格皆為 512 MiB production SOCKS5
round-trip、64 MiB warmup、七次 matched observations；除 MTU
fallback 格外，Proteus 固定使用已知路徑的 1452-byte MTU。

| cell | Proteus | Hy2 | uplift (95% bootstrap) | CPU P/H | RSS P/H |
|---|---:|---:|---:|---:|---:|
| 0% IID, 100 ms RTT | 199.85 | 110.18 | **+81.38%** (+77.50%, +85.63%) | 2.284 / 2.360 s | 30.75 / 91.59 MiB |
| 15% IID, 100 ms RTT | 90.67 | 69.96 | **+29.61%** (+20.56%, +33.24%) | 2.682 / 3.365 s | 32.68 / 198.55 MiB |
| 30% IID, 100 ms RTT | 59.30 | 49.55 | **+19.68%** (+15.29%, +34.02%) | 2.999 / 4.412 s | 33.28 / 204.29 MiB |
| moderate burst, 100 ms RTT | 160.25 | 104.05 | **+54.00%** (+48.47%, +58.26%) | 2.467 / 2.525 s | 32.15 / 146.37 MiB |
| severe burst, 100 ms RTT | 108.36 | 88.56 | **+22.35%** (+14.52%, +29.84%) | 2.560 / 2.816 s | 30.84 / 202.67 MiB |
| 5% IID, 20 ms RTT | 178.03 | 112.85 | **+57.76%** (+56.45%, +59.77%) | 2.199 / 2.401 s | 31.13 / 57.84 MiB |
| 5% IID, 300 ms RTT | 48.33 | 40.71 | **+18.71%** (+13.38%, +28.56%) | 2.830 / 5.033 s | 29.42 / 253.09 MiB |
| 5% IID, 100 ms RTT, MTU 1200 | 126.50 | 95.36 | **+32.65%** (+27.66%, +37.88%) | 2.840 / **2.631 s** | 33.76 / 180.90 MiB |

八格 throughput interval 全部高於零，雙方皆 7/7 成功；所有非零
loss/burst 格的兩向 qdisc 都有實際 drop。1452-byte 七格中，
Proteus 同時降低 client CPU 與 RSS。1200-byte 安全 fallback 是必須
保留的反例：吞吐與 RSS 仍勝，較多 packets 使 Proteus client CPU
比 Hy2 高約 8%。因此 current evidence 支持跨 loss、burst 與 RTT
的 sustained-bulk 優勢，不支持每一種 MTU 下所有資源維度都勝。

`2026-07-18-aes-mimalloc-expanded-matrix.jsonl` 每格保存七輪原始
throughput、CPU、RSS 陣列、bootstrap/permutation 統計、qdisc
counters、commit 與 image digest；以一格一行避免把 container logs
膨脹成數萬行。physical dual-host、reordering、short-flow 與至少
30 observations 的最終 promoted matrix 仍是封頂前置條件。

## 2026-07-18 ACK 恢復默認值校正

先前 benchmark harness 強制使用 RFC 9802 threshold `10`，與
Proteus 生產默認 `1` 不一致。固定 5% IID loss、100 ms RTT、
256 MiB payload，其餘條件完全相同的三輪診斷 A/B 顯示，threshold
`1`、`2`、`10` 的 Proteus median 依次為 116.39、111.78、98.98
MiB/s；對應 Hy2 median 約 87 MiB/s。這個篩選不承擔正式顯著性
結論，只用來選擇 recovery 參數。Harness、Compose、兩端模板與
entrypoint 因而統一回生產默認 `1`，CI 另加漂移檢查。

晉級後的 512 MiB、七輪 matched cells 都由乾淨的 `b0a03fb` 啟動，
使用同一組 version-pinned images 與 64 MiB warmup：

| cell | Proteus | Hy2 | uplift (95% bootstrap) | CPU P/H | RSS P/H |
|---|---:|---:|---:|---:|---:|
| 5% IID, 100 ms RTT | 131.33 | 95.22 | **+37.92%** (+32.67%, +41.30%) | 2.634 / **2.532 s** | 34.51 / 178.89 MiB |
| moderate burst, 100 ms RTT | 153.18 | 103.45 | **+48.07%** (+39.56%, +49.90%) | 2.532 / **2.367 s** | 30.49 / 149.91 MiB |
| severe burst, 100 ms RTT | 105.57 | 84.85 | **+24.42%** (+16.16%, +34.91%) | **2.674** / 2.775 s | 34.58 / 201.62 MiB |

三格雙方皆 7/7 成功，throughput interval 全部高於零，所有
loss/burst 格的雙向 qdisc 都留下實際 drop。IID 與 moderate burst
也保留了反例：Proteus client CPU 分別高約 4% 與 7%，因此結論仍是
sustained-bulk throughput 與 RSS 優勢，不宣稱每格、每個資源維度
皆勝。逐輪 throughput、image digest、commit、qdisc counters 與
摘要保存在 `2026-07-18-ack1-recovery-head-to-head.jsonl`。

## 2026-07-18 ACK=1 小流封頂格

同一條 warm production SOCKS5 carrier 上，每個 observation 建立
新的 SOCKS stream 並 round-trip 1 MiB payload。5% IID loss 與
severe Gilbert–Elliott burst 都使用 100 ms RTT、64 MiB warmup，
各跑 30 次：

| cell | Proteus | Hy2 | uplift (95% bootstrap) | p | CPU P/H | RSS P/H |
|---|---:|---:|---:|---:|---:|---:|
| 5% IID | 2.924 | 1.812 | **+61.34%** (+27.16%, +80.42%) | <0.00001 | 0.023 / 0.109 s | 31.64 / 88.70 MiB |
| severe burst | 2.917 | 1.799 | **+62.11%** (+7.20%, +71.25%) | 0.02099 | 0.023 / 0.107 s | 31.64 / 70.33 MiB |

兩格雙方皆 30/30 成功，兩向 qdisc 都記錄實際 drop。1 MiB
throughput 可換算為約 342/552 ms（IID）與 343/556 ms（severe
burst）的 median completion time。Severe burst 的 probability of
superiority 只有 0.678，顯示逐次分布仍重疊；可支持的是中位數與
分布檢驗勝出，不能宣稱每一條小流都更快。逐次觀測與完整環境指紋
保存在 `2026-07-18-ack1-short-flow-head-to-head.jsonl`。

## 2026-07-18 kernel 重排序反證與 threshold A/B

netem router 對兩個 egress 同時施加 5% packet reordering、25%
correlation 與 50 ms one-way delay；qdisc 前後快照證實兩向都有
數百萬至數千萬 packets 穿過 impairment，drop 維持為零。這是純
重排序格，不以丟包代替重排序。

生產默認 packet threshold `3` 的 64 MiB、30-run 格中，Proteus
median 24.65 MiB/s，Hy2 25.21 MiB/s，差 −2.25%；95% bootstrap
interval 為 −28.53% 至 +65.30%，p=0.594。它是明確反證：既有
loss/burst 優勢不能外推到 reordered path。

乾淨 commit `85c4339` 隨後比較 threshold `3`、`10`、`20`，每格
七次。對 Hy2 的中位數差依次為 −18.87%、−0.35%、−20.55%；
threshold `10` 是唯一值得晉級的候選，`20` 的三次小樣本假性大勝
在七次格消失。threshold `10` 的 30-run 正式格得到：

| metric | Proteus | Hy2 |
|---|---:|---:|
| median throughput | 26.17 MiB/s | 25.88 MiB/s |
| success | 30/30 | 30/30 |
| client CPU / run | 0.852 s | 1.191 s |
| client RSS | 28.53 MiB | 74.04 MiB |

throughput 表面 +1.14%，95% interval 卻是 −26.07% 至 +49.71%，
p=0.936，probability of superiority=0.508。因此可支持的結論只有
CPU/RSS 優勢與中位數劣勢被消除；沒有統計證據能宣稱 throughput
超越 Hy2。另以 256 MiB、5% IID loss 做三次 guard screen，
threshold `10` 仍為 118.94 對 86.74 MiB/s，兩向 qdisc 均有真實
drop，未見災難性 real-loss regression，但三次不足以晉級為正式
安全門檻。

逐輪 observation、兩個 30-run 反證、七次 threshold screen、
commit/image identity 與 qdisc counters 保存在
`2026-07-18-reordering-threshold-head-to-head.jsonl`。靜態 threshold
掃描到此停止；下一階段必須觀測 spurious loss，並以自適應
reordering tolerance 降低長尾，而非繼續提高固定數值。

後續 recovery telemetry 把原因再收窄。threshold `3` 與 `10` 的
30-run reordered cells，Quinn 宣告 loss 的總 packet 比例分別為
77.98% 與 76.71%，遠高於 kernel qdisc 的零 drop；同一 telemetry
在 5% IID loss guard 中為 4.95%，與實際 impairment 相符。這讓
QUIC-declared loss 成為可靠的 reordered-path 診斷訊號，但它仍是
代理量，不等同於逐 packet 證明的 spurious loss。

由 50 ms delay 與實測 packet rate 推導的 packet threshold `4096`
及 `16384`，搭配 time threshold `1.125`／`2.0` 做三次診斷後，
declared-loss total 仍介於 64.90%–74.06%，Proteus median 也沒有
單調改善；`16384/2.0` 甚至落後 Hy2 40.35%。因此 packet/time
threshold 靜態掃描正式終止。下一階段需比較 carrier-level probe
的 completion time、ACK/pacing 狀態與 recovery counters，再由
selector 換 carrier profile；不能從單一 loss ratio 直接推導參數。

補齊 server path 後，threshold `3` 的 client/server declared-loss
total 是 77.98%／67.39%；threshold `10` 是 76.71%／70.20%。
client 只改善 1.27 個百分點，server 反而惡化 2.81 個百分點，
解釋了 round-trip 吞吐為何沒有隨 client 指標同步改善。selector
必須逐方向評分，且 declared loss 只能觸發 probe，最後仍由 matched
completion time 與 real-loss veto 決策。

## 2026-07-19 confirmed-spurious adaptive recovery 與 severe reordering

固定 packet threshold 的實驗無法解決 severe reordering：Linux
`netem reorder 5% 25% delay 50ms` 會讓提早送出的 packet 越過數千個
仍在 delay queue 的 packet。Quinn 原本只有 128-bit packet-number
duplicate window，較晚抵達的合法 packet 因而在 loss recovery 之前
就被丟棄；把靜態 loss threshold 一路加大，只會把問題從 packet
threshold 移到 time threshold。

Quinn fork `9fd6f65e` 將 duplicate window 改為固定 16,384 packet
numbers、2 KiB/packet space 的 bounded ring bitmap，並只從遲到 ACK
證實的 spurious loss 學習 packet 與 time threshold。Packet threshold
上限為 16,384；time threshold 上限為 4 RTT。未出現遲到 ACK 的真實
loss 無法觸發調整，path migration 又會把門檻重設。Proteus commit
`5a8b8a9` 只在 inner triple-hybrid handshake 認證後啟用此機制；
matched probe 期間會暫停 adaptation，避免 A/B 自我污染。

同一 production SOCKS5 round-trip workload、64 MiB payload、64 MiB
warmup、100 ms RTT、1 Gbit/s target 的 promoted 30-run cell 結果如下：

| impairment | runs | Proteus | Hy2 | uplift (95% bootstrap) | client CPU / run | client RSS |
|---|---:|---:|---:|---:|---:|---:|
| reorder 5%, correlation 25% | 30 | 103.25 | 23.82 | **+333.39%** (**+232.47%, +569.07%**) | 0.285 / 1.429 s | 26.96 / 78.41 MiB |

兩方都是 30/30；Monte Carlo two-sided permutation p-value 經 add-one
correction 為 1/100,001，900 個跨樣本 pair 的 superiority probability
為 1.0。
兩端 qdisc drop 都是 0，證明差異來自指定 reordering 而非 queue
overflow。Proteus client/server 最終 packet threshold 都到 16,384，
time threshold 都到 2 RTT；量測期間 aggregate declared-loss ratio
分別只有 0.320% 與 0.263%。

真實 loss guard 沒有被越過。7-run IID screen 在 15% 與 30% loss 下，
兩端 packet threshold 均保持 3、time threshold 保持 1.125，adaptive
update 為 0；Proteus median 分別為 44.64 對 Hy2 37.65 MiB/s，以及
31.48 對 27.17 MiB/s。前者 95% interval 下界為 +1.72%，後者 interval
跨零，仍只是方向領先。兩個 Gilbert-Elliott 7-run cell 中，較溫和
cell 為 +12.61%（+8.08%, +26.84%）；更強 cell 只有 +1.18%，interval
−20.60% 到 +22.38%，必須保留為未解反例。

完整同機原始檔保留於 ignored evidence directories：
`bench/results/reorder5-adaptive-packet-time-30run-20260719/`、
`bench/results/iid-adaptive-regression-screen-20260719/` 與
`bench/results/burst-adaptive-regression-screen-20260719/`。這一輪證明
一個 severe-reorder cell 的顯著優勢與真實 loss 的 fail-closed 行為；
多種 reorder depth/correlation、跨 RTT、cross-host 與 independent
reproduction 仍未完成，不能寫成 universal cap。

## 2026-07-19 300 ms RTT severe reordering 與 warm-carrier 修正

第一輪 `reorder 5%, correlation 25%, one-way delay 150ms` screen
雖然顯示極大優勢，卻不是有效證據。Hy2 每次傳輸需 85–97 秒，
AB/BA 排程等待期間超過 Proteus 雙端寫死的 60 秒 QUIC idle timeout；
carrier 因 `TimedOut` 關閉後重新撥號，破壞了 per-cell-reset-then-warm
的共同生命週期。該結果保留為失敗證據，不進入性能結論。

Commit `2411637` 將 handshake deadline 與 reusable-carrier idle
deadline 拆開。Production 預設仍為 60 秒；benchmark 雙端明確使用
600 秒，metadata 會記錄該值。Runner 同時把任何 cell 內的
`β carrier closed` 或 α fallback 升格成硬失敗，防止日後再次把
重撥結果誤認為 warm-carrier throughput。

在 clean commit、重建 release image、相同 64 MiB payload／warmup
與相同 netem cell 下重跑七輪，結果如下：

| impairment | runs | Proteus | Hy2 | uplift (95% bootstrap) | client CPU / run | client RSS |
|---|---:|---:|---:|---:|---:|---:|
| reorder 5%, correlation 25%, 300 ms RTT | 7 | 44.33 | 0.676 | **+6454.16%** (**+4372.32%, +6722.46%**) | 0.465 / 71.094 s | 30.25 / 222.96 MiB |

雙方都是 7/7，exact two-sided permutation p-value 為
0.00058275，49 個跨樣本 pair 的 superiority probability 為 1.0。
兩端 qdisc drop 都是 0；cell 內 carrier close、stream-gap overflow
與 α fallback 都是 0。這次結果因此可以作為同機 severe-reordering
證據，而先前的 +4607% screen 不再引用。

仍須保留 recovery 反證。Proteus client/server aggregate
QUIC-declared loss ratio 是 45.53%／26.11%；它已能在深重排中維持
liveness 與 throughput，但 recovery classifier 仍把大量晚到 packet
先判成 loss。這不推翻 completion-time 優勢，卻表示下一輪研究應
降低 needless retransmission，而非繼續放大固定 window。精簡持久
證據位於
`notes/perf/2026-07-19-reorder-delay150-warm-carrier.jsonl`，完整 raw
logs 位於 ignored
`bench/results/reorder-delay150-warm-carrier-7run-20260719/`。

## 2026-07-19 broad reordering screen

修正 warm-carrier lifecycle 後，同一 clean harness 又掃過六個
reordering cells，交叉覆蓋 1%／5%／10% reorder、0%／25%／75%
correlation 與 20／100 ms RTT。每格七輪，每個 cell 都重建 client、
warmup 一次，再用固定 AB/BA 次序量測：

| reorder / correlation / RTT | Proteus | Hy2 | uplift (95% bootstrap) |
|---|---:|---:|---:|
| 1% / 0% / 20 ms | 149.11 | 9.06 | +1545.77% (+1378.85%, +1679.55%) |
| 1% / 25% / 100 ms | 163.27 | 79.41 | +105.59% (+83.85%, +114.20%) |
| 5% / 0% / 100 ms | 36.35 | 5.51 | +560.09% (+524.81%, +1010.41%) |
| 5% / 75% / 100 ms | 161.28 | 81.05 | +99.00% (+87.85%, +113.37%) |
| 10% / 25% / 100 ms | 51.55 | 2.73 | +1785.21% (+1528.24%, +2566.28%) |
| 5% / 25% / 20 ms | 183.56 | 98.29 | +86.76% (+70.23%, +97.50%) |

每格雙方都是 7/7；所有格的 exact two-sided permutation p-value 都
是 0.00058275，superiority probability 是 1.0。所有 client/server
qdisc drop、carrier close、α fallback 與 stream-gap overflow 都是
0。這批 screen 沒有吞吐反例；最低 uplift 的 5%／25%／20 ms 格
因此成為下一個 30-run promotion 對象，避免事後挑選最大勝幅。

持久摘要位於
`notes/perf/2026-07-19-reorder-broad-screen.jsonl`，完整 raw logs
位於 ignored
`bench/results/reorder-broad-warm-carrier-7run-20260719/`。這擴張了
同機 reordering 的證據面，仍不取代 physical cross-host 與
independent reproduction。
