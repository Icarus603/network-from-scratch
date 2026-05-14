# Off-Path TCP Exploits: Global Rate Limit Considered Dangerous

**Venue / Year**: 25th USENIX Security Symposium (USENIX Security 2016), Austin TX, August 10-12, 2016, pp. 209-225. **Best Paper Award** at the conference. CVE-2016-5696. Extended journal version: *IEEE/ACM Transactions on Networking* 26(2), pp. 765-778, 2018.
**Authors**: Yue Cao, Zhiyun Qian, Zhongjie Wang, Tuan Dao, Srikanth V. Krishnamurthy (UC Riverside) + Lisa M. Marvel (US Army Research Lab)
**Read on**: 2026-05-14（in lesson [1.8 TCP 連線管理](../../lessons/part-1-networking/1.8-tcp-connection-mgmt.md)）
**Status**: USENIX open access PDF available; abstract + main technique fully documented. Precis from abstract + extensive secondary literature (cited 200+ times). PDF not directly extracted but secondary corroboration via Semantic Scholar, UCR mirror, and IEEE/ACM TNET extended version.
**One-line**: 揭示 Linux kernel 3.6+ (2012) 實作 RFC 5961 challenge ACK 全局速率限制（default 100/sec）成為 **shared-state side channel**——blind off-path attacker 可在數十秒內推斷任意兩 host 是否有 TCP 連線並進一步推 sequence number，達成資料注入或斷線——「安全 mitigation 反成更強漏洞」的教科書級案例。

## Problem

歷史：
- **1985 Morris**：first published TCP ISN attack
- **2004 Watson "Slipping in the Window"**：blind off-path 注入只需 in-window seq（不需精確）→ ~2^16 攻擊量
- **2010 RFC 5961**：修補——RST 必須 seq 精確 == rcv.nxt 才直接接受；in-window 但不精確 → 回 **challenge ACK**（告訴對方「**我這邊認為這 RST 不合法**」）
- 但 RFC 5961 引入 **global rate limit**：每秒最多 N 個 challenge ACK（防 challenge ACK flood DoS）。default N = 100 (Linux)

「為什麼 global**？」**：實作簡單；防 DoS 不依賴 per-socket state。**但 global = 跨 socket shared = 任何 attacker 可消耗。**

## Contribution

四個核心 result：

#### 1. Connection inference 攻擊

Off-path attacker（不在 client-server 路徑上、不知道 4-tuple）能在數十秒內判斷 (src_IP, src_port, dst_IP, dst_port) 對應的連線**是否存在**。

#### 2. Sequence number inference 攻擊

在 connection 存在的情況下，**進一步**推斷 in-flight seq number 範圍。精度足以注入 RST 或 data。

#### 3. Demonstration: Tor de-anonymization 與 web injection

- **Tor**：對 Tor 出口節點對應的 4-tuple 做 sequence inference + RST injection → 終止 Tor circuits → 強迫 user 重連，重連時被 attacker 觀察 → 降低 anonymity
- **Plain HTTP**：對未加密 web traffic 注入 malicious HTML / JavaScript（典型 1990s style attack 在 2016 復活）

#### 4. CVE-2016-5696 與 cross-vendor 修補

提交給 Linux kernel maintainers，導致 Linux 4.7 (2016) 把 global rate limit 改為 per-socket。Android、ChromeOS、Ubuntu、Debian、RedHat 全部發 advisory。**全球數百萬 Linux 設備受影響**。

## Method (just enough to reproduce mentally)

#### 攻擊步驟

```
For each guessed (src_IP, src_port, dst_IP, dst_port):
    1. Attacker (spoof src=dst_IP, dst=src_IP, dst_port=src_port, src_port=dst_port)
       send SYN-ACK to dst (probe whether there's a connection)
       → If connection exists: server sees mismatched SYN-ACK → maybe challenge ACK
       → If no connection: server sees out-of-state SYN-ACK → RST

    2. Attacker measures how many challenge ACKs server emitted this second:
       From a side channel host (under attacker's control), attacker sends N invalid
       packets to the same server. If server emits ≤ (100 - k) challenge ACKs to
       attacker's host (where k > 0), it means some challenge ACKs went to victim
       connection probes → connection exists.

    3. If connection exists: refine 4-tuple, then sequence number.
       - Binary search seq:
         attacker sends RST with various seq values to dst.
         valid seq → no challenge ACK (RST directly accepted, but spoofed seq probably wrong)
         in-window non-match → challenge ACK consumed
         out-of-window → no challenge ACK
       - 透過觀察「challenge ACK budget」是否被消耗，推斷 seq 範圍
```

#### 量化

- **4-tuple 推斷**：~10-60 sec on typical home internet
- **Seq number 推斷**：~10-200 sec after 4-tuple confirmed
- **End-to-end attack**：總計 ~30 sec 到 ~10 min
- **Tor de-anonymization demo**：成功率 80%+ 在 controlled setup

## Results

#### 受影響系統

| OS | Linux kernel | 受影響 |
|---|---|---|
| Linux 3.6+ (2012-) | 預設 100/sec challenge ACK | ✅ |
| Android (Linux 3.6+ kernel) | 同 | ✅ |
| ChromeOS | 同 | ✅ |
| FreeBSD | 略不同實作 | 部分 |
| Windows | 不同 stack | ❌ 不直接適用（但有類似結構） |
| macOS | 不同 | ❌ |

#### 修補

- Linux 4.7 (2016) 把 challenge ACK rate limit 改為 per-socket
- IETF tcpm WG 後續 errata 對 RFC 5961
- Cloudflare、CDN provider 部署 firewall-level 緩解

## Limitations / what they don't solve

作者承認：

1. **被動觀察難偵測**：Defender 不容易發現 attack 進行中——traffic pattern 與正常流量極似
2. **必須對 server side 攻擊**：Linux client-server 對稱受影響，但典型 attack focus on server
3. **HTTPS 加密緩解 data injection**：對 TLS-encrypted 流量，attacker 仍可注入 RST 斷連但**無法注入 plaintext**——這個 partial mitigation 對 modern web 顯著
4. **Attack 需要時間視窗**：sequence inference 對 short-lived connection 不夠快——適合 long-lived（SSH、Tor relay、video stream）
5. **Linux 4.7 後 mitigated**：但**舊 device、IoT、Android 老 version** 仍 vulnerable——估計 10 年內全球仍有 millions of devices

## How it informs our protocol design

對 G6 的硬性教訓：

#### 1. 「Shared state for security」是 anti-pattern

任何想做 rate limit / token bucket / cache 的設計，**必須**：
- per-connection 或 per-flow，不可 global
- 若必須 global，**密碼學 binding to specific client**（HMAC of (client_id, request, ...)），讓 cross-client inference 不可行
- 若 global limit 存在，必須**timing-indistinguishable**——攻擊者無法從 timing 推斷他人狀態

#### 2. G6 server 設計具體 implications

- **不用 global rate limit**：所有 rate limit per-(client_id, connection_id, source_IP) tuple
- **不用 global counter**：所有計數器 per-flow 或 hash-of-flow 分桶
- **不用 shared cache**：state 完全 isolation per connection
- **anti-replay 用 per-session ticket**：不依賴 global nonce database

#### 3. QUIC 在這個攻擊面前的位置

QUIC RFC 9000 沒有 challenge ACK 概念（沒有 RST），所以 Cao 2016 直接不適用。**但 QUIC 自己的 rate limit / token / counter 設計仍可能犯同類錯誤**——例如 stateless retry token、connection ID rotation 邏輯。**G6 設計 review 必須對所有 shared-state mechanism 做 Cao 2016 風格 audit**。

#### 4. 「Mitigation 引入新攻擊面」的通用警告

RFC 5961 修補 Watson 2004 攻擊——但**引入更強漏洞**。**任何安全 mechanism 引入時要評估新 attack surface**：
- 新增 state → 是否 shared？
- 新增 message → 是否成為 oracle？
- 新增 timing constraint → 是否成為 side channel？

**G6 任何新 feature 必須過這個 review**。

## Open questions

- **Per-socket rate limit 是否就完全 safe**？Linux 4.7 之後 mitigation，但**理論上仍可能有 cross-socket 影響**（CPU scheduling、cache, ...）——open
- **QUIC 與類似 attack 的對應性**：QUIC 無 RST，但**有其他 stateful mechanism**（stateless retry token validity check、CONNECTION_CLOSE frame）——**可否被類似 side channel 利用**？尚無公開研究
- **針對 PQ TCP options 的 side channel**：未來 TCP-AO 升級到 PQ MAC（如 ML-DSA），**MAC 驗證的 timing 是否成為新 side channel**？open
- **AI 自動化發現 side channel**：Cao 2016 是 manual analysis；**ML / fuzzing 是否能自動發現類似漏洞**？Wang 2020 SymTCP 走這條，但仍 limited
- **Cross-tenant 雲端 side channel**：兩個 VM share host kernel TCP stack，是否有跨 tenant 的 challenge ACK 類 side channel？open
- **Detection of attack in progress**：是否有實時 detector？目前無——defender 通常事後從 log analysis 推測
- **應用層 protocol 是否該對 transport side channel 提供額外保護**：HTTP/2/3 是否該有 application-layer connection liveness check？G6 該不該設計 redundant heartbeat with crypto auth？

## References worth following

- **Watson 2004 *Slipping in the Window***（CanSecWest）— 直接前因
- **RFC 5961** — 被本文揭露漏洞的 spec
- **Linux kernel 4.7 release notes** — patch
- **Feng et al. 2020 CCS *Off-Path TCP Exploits of the Mixed IPID Assignment*** — 同 lab 後續，IPID 側信道
- **Wang et al. 2020 NDSS *SymTCP*** — 自動化 TCP DPI evasion discovery
- **Zhiyun Qian's lab page** <https://www.cs.ucr.edu/~zhiyunq/> — 持續 networking security research
- **USENIX Best Paper Awards** — Cao 2016 為 2016 USENIX Security Best Paper
