# Peer-to-Peer Communication Across Network Address Translators

**Venue / Year**: USENIX Annual Technical Conference (USENIX ATC '05), Anaheim CA, April 2005.
**Authors**: Bryan Ford (MIT), Pyda Srisuresh (Caymas Systems), Dan Kegel (independent)
**Read on**: 2026-05-14（in lesson [1.7 NAT 完整分類學](../../lessons/part-1-networking/1.7-nat-taxonomy.md)）
**Status**: Citation widely corroborated across IETF BEHAVE WG documents (RFC 4787, RFC 5128) and WebRTC literature. PDF freely available via USENIX open access. Precis based on author secondary materials, RFC 5128 (Srisuresh et al. 2008 IETF SoK) which is the IETF-codified version, and Kegel's earlier 1999 white paper which precedes this work.
**One-line**: 系統 codify「hole punching」技術——讓兩端都在 NAT 後的 peer **同時送 UDP/TCP packet 到對方 STUN-discovered public mapping**，繞過 EIM-based NAT 的 filtering 規則建立直連——奠定後續 STUN/ICE/TURN/WebRTC 整套 P2P over NAT stack。

## Problem

2000s 中：
- 90%+ residential broadband client 在 NAT 後（IPv4 exhaustion 加 home router 普及）
- P2P 應用（Skype voice、BitTorrent、Gnutella、online gaming）需要直接 peer-to-peer 連線以避免 server-side bandwidth costs
- 標準 client-server 模型不適用：兩端皆在 NAT 後時，**任一端都無法主動 inbound 連對方**

但學界 / 工業界**缺乏統一術語**描述 NAT 行為與穿越技術。Skype 用一套自己的閉源 P2P NAT traversal、BitTorrent / DHT 各有 ad-hoc 方法。**通用、可重複實作、可分析的 NAT traversal 技術**尚未明確化。

## Contribution

四個主要貢獻：

#### 1. NAT 行為分類（4-class 起源）

提出 NAT 行為 4 分類（後來被 IETF 採為 RFC 3489 術語，再被 RFC 4787 改進為 2D 分類）：
- **Full Cone**：mapping 對任意外部 endpoint 重用 + 任意外部 endpoint 都可送 inbound（=今日 EIM + EIF）
- **Restricted Cone**：mapping 重用 + 僅允許曾被 outbound 過的 IP 送 inbound（=EIM + Address-Dependent Filtering）
- **Port Restricted Cone**：mapping 重用 + 僅允許曾被 outbound 過的 IP:port 送 inbound（=EIM + APDF）
- **Symmetric**：mapping 對不同外部 endpoint 不重用，每 4-tuple 各自 mapping（=APDM）

**這個分類在當時是進步**——但 RFC 4787 後續指出 mapping 與 filtering 應分開描述（2D 比 1D 4-class 更精確）。

#### 2. UDP hole punching 技術 codification

形式化「**hole punching**」步驟：

1. Client A 與 B 各自 outbound 連 rendezvous server S，獲取 mapping (Ax, Ax_p) 與 (Bx, Bx_p)
2. S 把對方 mapping 告知雙方
3. **A 與 B 幾乎同時** 送 packet 到對方 mapping
4. 對 NAT-A 而言：A → (Bx, Bx_p) 是 outbound，建立 mapping
5. 對 NAT-A 而言：來自 (Bx, Bx_p) 的 inbound packet——因 mapping 已存在 → 接受
6. 雙向同樣，建立 P2P UDP connection

**可行性**：適用 Full Cone / Restricted Cone / Port Restricted Cone。對 Symmetric **不可行**（必須走 relay）。

#### 3. TCP hole punching 技術

TCP 比 UDP 難很多倍——TCP 必須完成 3-way handshake，且 NAT 對 TCP outbound 看到 ACK 才完成 mapping：

- **Simultaneous open**：雙方 simultaneously 送 SYN；雙 NAT 看到 outbound SYN 建 mapping，inbound SYN 看似合法 → forward；雙方各進 SYN_RECV → 互回 SYN+ACK → ESTABLISHED
- **Sequential SYN approach** with SO_REUSEADDR：複雜的時序操作

實測：UDP hole punching ~82% NAT 組合下成功，TCP hole punching ~64%（因 NAT 對 TCP 的 stateful 處理 inconsistent）。

#### 4. Hairpinning 識別與 requirement

形式化「同 NAT 下兩 client 都用 public mapping 互連」場景——指出大量 home NAT **不支援 hairpinning**——這個 deficiency 是 P2P deployment 的隱性障礙。**後被 RFC 4787 REQ-9 強制要求**。

## Method (just enough to reproduce mentally)

#### 大規模量測

作者部署 5 個 STUN-like server 跨 4 個國家，邀請 380 個志願者從不同 NAT 環境連，量測：
- mapping behavior（不同外部 endpoint 是否 reuse port）
- filtering behavior（不同 source 能否 inbound）
- hairpinning 支援
- TCP simultaneous open 行為

#### 分類結果（2005 時的工業 NAT 分布）

| NAT 類型 | UDP 比例 | TCP 比例 |
|---|---|---|
| Full Cone | ~36% | ~24% |
| Restricted Cone | ~27% | ~36% |
| Port Restricted Cone | ~27% | ~16% |
| Symmetric | ~8% | ~22% |
| Hairpin 支援 | ~28% | ~30% |
| Unknown / failed | ~2% | ~2% |

⇒ ~90% NAT 可 hole-punch（UDP）；Symmetric 只佔 ~8%——對 P2P 應用是 acceptable success rate。

#### Hole-punch demonstration

實際 deployment：作者把演算法整合進 P2P file-sharing app，量測 connection establishment success rate ~85% UDP / ~62% TCP——驗證理論。

## Results

- **UDP hole punching 成功率**：~82% across diverse NAT pairs
- **TCP hole punching 成功率**：~64%
- **Hairpinning**：~28% NAT 支援（**主要 deficiency**）
- **影響**：後續 Skype、BitTorrent DHT、libnice (GNOME)、Pion WebRTC、libp2p 全部繼承 hole punching 技術

論文發表後：
- IETF BEHAVE WG 在此基礎上制定 RFC 4787 (BCP 127, 2007) 與 RFC 5382 (BCP 142, 2008)
- 4-class NAT 術語廣泛採用，後被 RFC 4787 升級為 2D 分類
- WebRTC（2011 起）整套 P2P stack 直接建立於本論文與後續 RFC 之上

## Limitations / what they don't solve

作者承認：

1. **Symmetric NAT 不可解**——只能走 TURN relay 中繼
2. **Carrier-Grade NAT (CGN) 尚未普及**：2005 年 CGN 是 future scenario，**雙層 NAT 與 CGN 場景未深入處理**
3. **Hairpinning deficiency 在工業界普及前需多年**：直到 RFC 4787 強制要求後才慢慢改善
4. **TCP simultaneous open timing 極脆弱**：精確 timing 需要 round-trip 知識，**真實 internet 時序變化大導致實際 ~30-40% 成功率**（不是論文 64% 受控環境數字）
5. **沒有討論 IPv6 影響**：論文時 IPv6 尚未實質部署
6. **沒有考慮 active attacker**：論文威脅模型純粹「能否連通」——**對 GFW-style adversary 主動探測無對抗策略**

## How it informs our protocol design

對 Proteus 影響：

1. **Proteus baseline 選 client-server 避開 hole punching 複雜度**：本論文 + 後續 20 年 ICE 工程實證——P2P-over-NAT 永遠是 ~85% 成功率 + 10-15% 退路 + 複雜 fallback。**對審查抗性協議**這個複雜度與失敗率不可接受。**P2P 留 v2 evaluate**。

2. **若 Proteus v2 走 P2P**：必須完整實作 ICE（**不是簡化版**）——包括 host / srflx / prflx / relayed 4 種 candidate 與所有 connectivity check 邏輯。Pion WebRTC 是 reference 實作。

3. **Symmetric NAT 場景必須 TURN fallback**：~10-30% mobile CGN 用戶屬此類——**沒有 fallback 等於放棄這群人**。

4. **Hole punching 的 timing pattern 是 fingerprint**：simultaneous send 的精確 timing 與 packet size pattern 對 GFW 視角極可識別——**P2P Proteus 在審查場景的 cover traffic 設計必須隱藏 hole-punch 特徵**。

5. **Hairpinning 的 Proteus 場景**：self-hosted Proteus server + same-LAN client → 觸發 hairpin。OS 對 hairpin 處理 inconsistent——**client 必須有 LAN fallback**（mDNS 或固定 LAN IP）。

## Open questions

- **2026 NAT 行為分布**：本論文 2005 量測。20 年後分布已大幅改變（CGN 興起、IPv6 部分採用、ISP-supplied router 標準化）。**最新大規模量測極缺**——後續論文（Maier 2011 PAM、Wang 2017 IMC）只 partial 更新
- **CGN-of-CGN（多層）的 hole punch 可行性**：mobile carrier 多層 CGN 場景，hole punching 完全失敗。**理論可行性是否存在**？open
- **Quantum-resistant rendezvous**：STUN server 是 single point of trust——**去信任化 rendezvous** 可基於 DHT / blockchain？學術探討
- **GFW 場景下的 P2P 偽裝**：本論文不考慮審查對手——**「hole punching pattern 不被識別為 P2P」這個性質要怎麼設計**？open
- **eBPF-based programmable NAT**：Linux XDP/eBPF NAT 可程式化——能否設計**「對 hole punching 友善」的 enterprise NAT**？open
- **後 IPv6 時代 NAT 死亡的可能性**：若 IPv6 全面部署，NAT 在邏輯上不再 mandatory（每個 device 有 unique address）——但 firewall 仍存在。**「沒有 NAT 但有 stateful firewall」的時代** P2P 是否簡化？open

## References worth following

- **RFC 4787 (BEHAVE WG, 2007)** — 直接繼承並 generalize 本論文
- **RFC 5128 (Srisuresh, Ford, Kegel 2008)** — IETF SoK of P2P communication across NAT, 同 author 的 codification
- **RFC 8445 (ICE 2018)** — 工程化完整 stack
- **RFC 8489 (STUN) + RFC 8656 (TURN)** — connectivity establishment 工具
- **Maier et al. 2011 *NAT Usage in Residential Broadband Networks***（PAM）— 較新量測
- **Tailscale Engineering blog** — 持續更新 P2P NAT 工程經驗
- **WebRTC for the Curious** 開源書 — 工業界 P2P stack
- **libp2p Hole-Punching Spec** — modern P2P framework 視角
- **Pion WebRTC (Go)** — 開源 reference 實作
- **Mathy Vanhoef 2023 TunnelCrack** — P2P + VPN 互動的新攻擊面
