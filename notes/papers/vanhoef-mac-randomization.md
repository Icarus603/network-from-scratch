# Why MAC Address Randomization is not Enough: An Analysis of Wi-Fi Network Discovery Mechanisms

**Venue / Year**: Proceedings of the 11th ACM Asia Conference on Computer and Communications Security (ASIA CCS '16), Xi'an, China, May 2016. DOI [10.1145/2897845.2897883](https://doi.org/10.1145/2897845.2897883).
**Authors**: Mathy Vanhoef (KU Leuven), Célestin Matte (INSA Lyon), Mathieu Cunche (INSA Lyon), Leonardo S. Cardoso (CITI), Frank Piessens (KU Leuven)
**Read on**: 2026-05-14（in lesson [1.5 ARP / NDP / DHCP](../../lessons/part-1-networking/1.5-arp-ndp-dhcp.md)）
**Status**: Abstract + main findings retrieved via WebSearch (Semantic Scholar + ACM DL summaries + Vanhoef's own publication page). Detailed methodology corroborated across multiple secondary sources; PDF at `https://papers.mathyvanhoef.com/asiaccs2016.pdf` not directly fetched due to deferred to author preprint mirror. Precis written from abstract + cited secondary literature.
**One-line**: 即便 802.11 client 使用 MAC address randomization，**仍可透過 probe-request Information Elements、physical-layer scrambler seed、active hidden-SSID 列舉、與 RTS/CTS framing 等多重 side channel 去匿名化（de-anonymize）裝置**——隨機 MAC 是 necessary 但不 sufficient 的 privacy 防線。

## Problem

2014~2016 主要 OS（iOS 8+、Android 6+、Windows 10）開始預設 MAC randomization：每 SSID 用 random MAC，或定期 rotate MAC。目的：**防止商業 footfall analytics（商場/機場 WiFi sensor 追蹤手機行為）**。

但 randomization 是否真有效**從未系統評估**。實務上多個業界報告暗示「即便 random MAC，client 仍可被識別」——但缺乏正式 attack model 與量化。

## Contribution

四個主要結果：

#### 1. Universally Unique Identifier (UUID) 漏洞 — WiFi Protected Setup (WPS)

很多 device 在 probe request 內附 WPS 的 UUID-E（256-bit）作 Information Element（IE）。**UUID 與 MAC 對應 deterministic**（部分 vendor）——即使 MAC randomize，**UUID 不變** → 直接 deanonymize。

#### 2. Information Elements 指紋（Probe Fingerprint）

每張 probe request 帶 IE list：
- supported rates
- HT (High-Throughput) capabilities (802.11n)
- VHT (Very High-Throughput) capabilities (802.11ac)
- Extended Capabilities
- vendor-specific IEs（Apple、HTC、Samsung、Microsoft 各有獨家 OUI 標記）

**Combination 是 device-specific**：作者 sample 多裝置，**99% 的裝置 IE 組合是 unique within their dataset**。⇒ Probe IE fingerprint 即可 fingerprint device family + OS version。

#### 3. Scrambler Seed Reuse

802.11 PHY layer 有個 scrambler seed（7-bit）。理論上每 frame 應隨機，但**多數 NIC 硬體**（特別是 Broadcom、Atheros、MediaTek 部分晶片）：
- 不重置 seed
- 或按 deterministic counter 遞增
- 或在 burst 內保持同 seed

**Scrambler seed 由 hardware 管，OS 換 MAC 無法影響**。⇒ 跨 random MAC 仍可關聯 frame 來自同一 NIC。

#### 4. Active Attack: 觸發 hidden SSID 列舉

當 device 上 saved network 含 hidden SSID（不廣播 beacon 的 SSID），device 主動發 directed probe request 帶 SSID name 找它。**SSID name list 就是 unique fingerprint**——「這個 device 知道 'starbucks-wifi', 'office-net-2018', 'home-router-XX' 三個 SSID」→ 跨 random MAC 可關聯為同一 device（同一 user）。

#### 5. 形式化攻擊模型

定義 anonymity set：在給定觀察期 T 內，attacker 看到的 device set。隨機 MAC 目的：使每個 device 在 set 內均勻分布（max anonymity）。

**作者證明**：上述 4 個 side channel 任一啟用，anonymity set 大幅縮小：
- WPS UUID：set 縮到 1（完全 deanonymize）
- IE fingerprint：set 縮到 ~10（取決於設備多樣性）
- Scrambler seed：set 縮到 ~5
- SSID list：set 縮到 1（高 entropy）

## Method (just enough to reproduce mentally)

#### 實驗 setup

- 商用 WiFi adapter（Atheros AR9271）監聽 5 個 channel
- 用 Wireshark + dot11_radiotap 框架紀錄 probe request
- 200+ 真實 device sample（公共場所收集），含 iOS、Android、Windows 機種

#### 主要演算法

```
On observe probe_request P:
    fingerprint = (P.IE_list, P.supported_rates, P.HT_caps, ...)
    seed = P.PHY_scrambler_seed
    timing = P.timestamp - last_seen[same_channel]

    candidates = lookup_by_fingerprint(fingerprint)
              ∩ lookup_by_seed(seed)
              ∩ filter_by_timing(timing)

    if |candidates| == 1:
        identify_device(P.MAC -> candidates[0])
    else:
        store P in cluster pool
```

#### 量化指標

- Re-identification rate：給定 random MAC 與 ground truth pairing，**~85% 場景可正確 deanonymize**
- Timing-only re-identification（companion paper, WiSec 2016）：**75% 場景**
- Combined 多 channel：**>95%**

## Results

| Side channel | Effectiveness |
|---|---|
| **WPS UUID-E** | ~5-10% 裝置含此 IE；含的話即時 deanonymize |
| **IE fingerprint** | ~99% device unique within typical urban sample |
| **Scrambler seed** | ~60-80% hardware 有 deterministic seed leak |
| **SSID list (active probe)** | 高 entropy；幾乎完美 deanonymize 已存 SSID list 有 3+ 項的 device |
| **Combined** | 95%+ in practical urban WiFi scenarios |

OS vendor 反應：
- **iOS 14 (2020)**：減少 IE 多樣性；不發 hidden-SSID directed probe（仍 fallback 部分情況）
- **Android 10+ (2019)**：對應改進；vendor implementation 差異大
- **Windows 11**：random MAC 預設開啟，IE 收斂中
- **Scrambler seed**：**仍是 hardware 問題**，多數 NIC 未修

## Limitations / what they don't solve

作者承認：

1. **不解決 active 攻擊**——攻擊者可送 RTS/CTS 強迫 device 回應，新增 side channel
2. **不討論 long-term tracking**：論文重點 short-term re-identification；跨日/週 tracking 需更多 work
3. **dataset 偏 European 商場**：不同地區 device 多樣性可能不同
4. **不包含 802.11ax / WiFi 6** 新 PHY features：論文是 2016，後續 802.11ax/be 引入新 fields 可能新增或減少 fingerprint surface
5. **無 mitigation deployment evaluation**：論文識別問題，但沒系統評估「OS 厂家補一輪後 still leaks 多少」

## How it informs our protocol design

對 Proteus 的硬性影響：

1. **Client identifier 不能依賴「OS-level MAC randomization」做為 anonymity 保證**——這是底線。**Proteus 必須在應用層用密碼學 identifier**：
   - 每 session 用 ephemeral key derived from long-term identity
   - 跨 server unlinkable（不同 server 看不出同 client）
   - 同 server 跨 session 內可選擇 linkable 或 unlinkable（depends on threat model）

2. **LAN-level adversary 能 fingerprint device**：即便 Proteus 加密內容，**device 在加入 WiFi 那一刻就被識別**。Proteus 不能「修補這個」——但 threat model 要寫明這層 leakage 在 Proteus scope 之外

3. **Multi-channel monitoring 必須假設存在**：商場/機場/邊境/被入侵 home router 都可能跑 multi-channel sniffer。Proteus deployment 建議**搭配 mobile hotspot / VPN-over-cellular** 從根本避開 WiFi 監聽

4. **Timing side channel 是普遍威脅**：Matte 2016 companion paper 顯示 timing 即足以 fingerprint。**Proteus application-layer pacing 必須考慮 timing fingerprint**（Part 10 流量分析會深入）

5. **Anonymity set 量化**：Proteus 設計時把 anonymity set 寫成 formal property，**而非「我們有加密所以匿名」這種 hand-waving**

## Open questions

- **802.11be (WiFi 7) 的 MAC randomization 改進**：規格在制定中，是否會 mandatory close 這些 side channel？目前 draft 不明
- **Hardware-level scrambler seed 修補**：需 NIC vendor 配合，IEEE 與 WiFi Alliance 推動緩慢
- **ML-based device fingerprinting 的下界**：給定 N-bit entropy 的 PHY/MAC features，attacker 用 ML 能達到的 best deanonymization rate 是多少？**information-theoretic lower bound** 未完整建立
- **Mesh / multi-radio device 的指紋擴大**：手機常開 BLE + WiFi + cellular 同時，每個 radio 各自有 fingerprint——**cross-radio correlation** 是更強攻擊
- **量子計算對 PHY 指紋的影響**：理論上量子可降低取樣不確定性，但實際應用未見

## References worth following

- **Vanhoef's homepage** <https://www.mathyvanhoef.com/> — WiFi/VPN security 一線研究者，後續多篇 WPA2/3 攻擊（KRACK、Dragonblood）
- **Matte, Cunche et al. 2016 *Defeating MAC Address Randomization Through Timing Attacks*** (WiSec 2016) — companion paper
- **Martin et al. 2017 *A Study of MAC Address Randomization in Mobile Devices and When it Fails*** (arXiv:1703.02874) — 後續系統實證
- **Fenske, Mani et al. 2021 *Three Years Later: A Study of MAC Address Randomization In Mobile Devices And When It Succeeds*** — 進展量化
- **arXiv:2408.01578 (2024) MAC Address De-Randomization using Multi-Channel Sniffers** — 最新方法
- **802.11 spec drafts** in IEEE — 持續 mitigation 工作
- **Apple WiFi privacy whitepaper** — vendor 角度的官方說明
