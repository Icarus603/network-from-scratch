# 問題：2026 年 3、4 月份 GFW 在哪些方面發力？最近商用節點大量「死亡」是怎麼回事？我們下一步要重點防禦什麼？

## 背景

使用者在開發 Proteus 的安全 + 速度雙料 SOTA 目標下，需要把握 2026 年到目前為止 GFW 的真實攻勢，避免設計鎖死在過時威脅模型上。重點補位 2025 年 9 月 Geedge/MESA 600 GB 洩漏 *之後* 的進展 —— 那是一年前的東西了，圈子發展極快。

對應到課綱：[Part 9 GFW 研究](../SYLLABUS.md)、[Part 11 設計](../SYLLABUS.md)，特別是 11.3（威脅模型）與 11.5（傳輸層選擇）。

## 回答

下面把 2025 Q3 → 2026 Q2 GFW 的攻擊面拆成 **七條主線**，每條都標清：
- **WHAT**：技術機制（不是新聞口號）
- **WHEN**：時間軸與一手來源
- **WHY 對我們致命**：Proteus 當前覆蓋程度
- **TODO**：roadmap 上要新增/補強的具體 issue

最後一節是統合的「Proteus 2026 防禦覆蓋矩陣」。

---

### 主線 1：Geedge/MESA 600 GB 文件洩漏（2025-09-11） — **產品線曝光，不只是源碼**

**WHAT**

2025-09-11 約 500–600 GB 內部 Jira / Confluence / GitLab 倉庫從 Geedge Networks（方濱興一手創立的商用 GFW 廠商）+ 中科院信工所 MESA Lab 流出。曝光的不只是檢測算法，而是 **產品架構 + 客戶部署 + 政策推送機制**。已命名的產品：

| 模組 | 角色 |
|---|---|
| **Tiangou Secure Gateway (TSG / TSG8)** | 邊界 DPI 旗艦，HTTPS / TLS / VPN 識別、ML 行為分析、SSL/TLS 攔截 |
| **Cyber Narrator** | 操作員儀表板（white-label 給客戶國家用）|
| **TSG Galaxy** | 流量資料倉儲 + 離線分析後端 |
| **Network Zodiac** | 系統監控 + alert |
| **AppSketch Works** | 「應用識別規則」維護介面，客戶本地可定義要 block 哪些 VPN/proxy 名單 |

關鍵能力（從 InterSecLab + Amnesty + GFW.report 的二手分析中可確認）：
- 跨部署的 **共享黑名單資料庫**：VPN/proxy/Tor 橋的 IP 跨國累積
- 9 個商用 VPN 已被標記為「resolved（已破）」
- **能對抗 Belt-and-Road 出口客戶網路**做主動探測 + IP 評分
- 部署過的客戶國：緬甸（26 個資料中心，81M 並發 TCP）、巴基斯坦、衣索比亞、哈薩克
- 中國省級已部署：新疆、江蘇、福建（地區性 GFW 補位主 GFW）

**WHEN**：洩漏 2025-09-11；GFW.report 2025-09-15 首篇分析；InterSecLab 76 頁技術報告 + Amnesty 102 頁報告 2025-09-18 同步發布。**源碼本身的逐函式分析至今 (2026-05) 仍在進行中，沒有公開的完整 reverse engineering**。

**WHY 對我們致命**

Tiangou 的 SSL/TLS 攔截 + ML 行為分析 ≠ 古典 DPI 簽名匹配。我們不能假設「TLS 1.3 + Chrome JA4 + Reality 偽裝」這個 stack 還是 2024 的 baseline。商用 GFW 出口意味著對手有 **持續迭代預算** —— 不是一次性的學術論文 PoC。

**Proteus 當前覆蓋**：
- ✅ JA4 已對齊 Chrome cipher / sig_algs / compress_certificate
- ✅ Cell-split padding 摧毀 sub-quantum 長度信號
- ✅ Cover-traffic heartbeats 摧毀 active/idle 時序信號
- ❌ uTLS-grade bit-perfect ClientHello（cipher_count / ext_count 還是 09/11 vs Chrome 15/17）
- ❌ 對抗 **跨部署 IP 共享黑名單** —— 我們沒有 IP 輪替策略，operator 自己拿到一個被列入 Tiangou 黑名單的 VPS 就完蛋

**TODO**：
1. **uTLS 集成（M3）**：fork rustls 的 ClientHello assembler，把 cipher_count / ext_count 補上去，徹底消滅 JA4 殘餘差異。這是 README 已標 ❌ 的單一 leading gap。
2. **IP 健康預檢工具**：`proteus-server preflight --check-ip-reputation`，部署前查 VPS IP 是否已在已知 GFW 黑名單（Censys / Shodan / GFW.report 的 IP feed）。**這是 operator-level 防禦，但我們必須提供工具**。
3. **新增 spec §11 威脅模型小節**：明確列入「Tiangou-class 商用 DPI + 跨部署黑名單」作為 Tier-1 對手。

---

### 主線 2：2026-04 機場節點「大規模死亡」 — 物理拔線 + 運營商斷線

**WHAT**

2026-04-01 起，廣東、上海、北京等省級的多家 IDC 配合執法部門，**物理拔線 + 斷電** 大量被指認的中轉節點。和傳統「IP 被封」不同，這次是 **硬體層** 處置：機架上的網線直接拔掉、機器直接關電。

機制鏈：
1. 執法部門自 2025-05 起 **主動購買** 機場訂閱（[中國人權 2025-07-23](https://x.com/hrichina/status/1948588695713710525) 報告佐證）
2. 從訂閱裡導出節點 IP 清單
3. 通過 ISP 反查節點所在 IDC
4. 2026-04-01 同步命令 IDC 物理斷開

被打的協議：Shadowsocks、V2Ray (VMess)、Trojan、VLESS（部分 Reality 也被波及 —— 因為打的是 IDC 不是協議）。**中轉機場（跨境專線）受擊最重**，因為它們依賴中國境內中轉伺服器；純境外 + 直連架構受影響較小。

**WHEN**：
- 2025-05 主動購買訂閱開始（HRC 報告）
- 2025-08-20 GFW 對 TCP/443 做 74 分鐘無條件 RST 注入（已有 precis：[notes/gfw/2025-08-20-port443-rst-incident.md](../notes/gfw/2025-08-20-port443-rst-incident.md)）
- 2026-03 中下旬：機場上游被通報「拔線」首輪 ([Paolujichang issue tracker](https://github.com/limbopro/Paolujichang))
- 2026-04-01：大規模物理斷網 ([RelyVPN April 2026 報告](https://relyvpn.com/blog/china-vpn-crackdown-2026.html))
- 2026-04–05：拔線潮持續升級，「中轉機場」進入無線路可換境地

**WHY 對我們致命**

這不是協議層問題，而是 **部署模型** 問題。Proteus 即使設計再完美，operator 若依賴中國境內中轉 → 一樣被拔線。但這也是我們可以 **正面解決** 的：

- 純境外部署 + 客戶端從本機直接 dial 境外 VPS（無中轉）→ 不在這次打擊範圍內
- 但 **GFW 對純境外連線的能動性正在上升**（見主線 3 + 主線 5）

**Proteus 當前覆蓋**：
- ✅ 設計上就是 client → VPS 直連，無境內中轉依賴
- ✅ `proteus-client validate` 已能預檢配置
- ❌ 沒有 **deployment topology 建議文檔** —— operator 不知道「不要用中轉」是死命令
- ❌ 沒有 multi-VPS 自動故障轉移（spec §10.4 multipath QUIC 還沒做）

**TODO**：
1. **`deploy/README.md` 增加「Topology Recommendations」一節**：明確警告中轉架構在 2026-04 後已死，推薦直連 + multi-region active-active。
2. **Multi-VPS HA 客戶端模式**（M3）：`server_endpoints: [a, b, c]`，當前 endpoint 連續 3 次握手失敗 → 自動 fail over，無需操作員介入。
3. **健康探測**：客戶端每 N 分鐘對備用 VPS 做隱蔽性 keepalive（藏在 cover-traffic 裡），第一手感知 endpoint 不可用。

---

### 主線 3：QUIC SNI 審查全面部署（USENIX Sec '25 + 2025–2026 持續加碼）

**WHAT**

GFW 在 QUIC Initial 上做 SNI inspection 從 2024 試水，2025–2026 已全國穩定部署。詳細機制見 [zohaib-quic-sni-usenix25.md](../notes/papers/zohaib-quic-sni-usenix25.md)：
- 三種 residual censorship：3-tuple 58% / 4-tuple 37% / 無封鎖 5%
- 觸發後約 3 分鐘 residual block 期
- 「source port ≤ destination port 才檢測」是已記錄的 GFW 自我設計選擇 → 可利用
- 「只看 flow 第一個 datagram」是已記錄的 GFW 性能優化 → 可利用

**WHEN**：論文 2025-08 USENIX Security；GFW.report 2025-08 開始追蹤；2026 持續報導 GFW 對 Hysteria2 / TUIC 加強識別 + UDP throttling。

**WHY 對我們致命**

β profile 是純 QUIC，如果 SNI 在明文 TLS ClientHello 內就完蛋。我們已 **戰術性對抗** 三個 USENIX 25 技巧（commit `e51ccf9` / `5d0209d` / `8e33367`），但 **沒有從根本上隱藏 SNI**。

**Proteus 當前覆蓋**：
- ✅ Source-port walk `[max(1024, dst-7) .. dst]`（USENIX 25 #1 evasion）
- ✅ 16-byte prefix-noise datagram before QUIC Initial（#2）
- ✅ Connection migration API（#4，逃 180s 5-tuple drop）
- ✅ Pad-to-MTU（operator 可選，#5 等效防禦）
- ❌ **ECH（Encrypted Client Hello, RFC 9460 + draft-ietf-tls-esni-22）**：spec §7.4 列為 M3，目前 SNI 還是明文 `vps.example.com`
- ❌ HTTPS RR 發布 + ECH key 輪轉

**TODO**：
1. **ECH 實作（M3 / spec §7.4）**：升到 P0。沒有 ECH 等於 SNI 公開，所有 prefix-noise / migration tricks 都是治標。需要：
   - rustls ECH client / server 支持（rustls 0.23 有 prototype）
   - 配置 cover-URL 的 HTTPS RR ECH key
   - 自動輪轉 ECH key 的 operator workflow
2. **Spec 補充**：明確 β profile 在「ECH 不可用」（如客戶端 DNS 被劫持）時的降級策略：拒絕連線，不是 SNI 明文。
3. **新增 wire-level 測試**：`quic_ech_sni_protection.rs` — 模擬 GFW 取 first datagram，assert SNI 不可見。

---

### 主線 4：商用節點 IP 範圍預封 + 主動探測升級

**WHAT**

GFW 2025–2026 不再只是「等流量出問題才封 IP」。新模式：
- **預封**：自動掃描雲廠商 IP 段，看哪些段被機場集中使用 → 段級封鎖
- **主動探測升級**：對可疑 IP 發送 **應用層 probe**（不只是 TCP SYN）。對 TLS 服務發 ClientHello，看 ServerHello 是否「像 nginx」；對 QUIC 服務發 Initial，看 Retry / Handshake 行為
- **跨 ISP 黑名單同步**：一個 IP 在電信被認定就同步到聯通 / 移動

**WHEN**：[net4people/bbs #519](https://github.com/net4people/bbs/issues/519) 持續追蹤；Xray issue [#5332](https://github.com/XTLS/Xray-core/issues/5332) 報告 Reality 在俄羅斯（Iran/Russia 經常作為 GFW-class 對手的前哨）2025-11 開始出現「Failed to read client hello」等失效

**WHY 對我們致命**

Proteus 的 active-probing 防禦是「byte-verbatim cover-server splice」（auth 失敗就把流量原樣轉發到真實 HTTPS 伺服器）—— 這對抗 *請求* 的探測，但無法對抗 *時間序列* 的探測（GFW 多次重試打到同一個 cover-URL，看 IP 行為差異）。

**Proteus 當前覆蓋**：
- ✅ Cover-server pass-through on auth fail（p99 < 1 ms，spec §5.7）
- ✅ Real TLS 1.3 outer with valid cert
- ✅ 三層 rate limiter：global handshake budget + per-IP token bucket + per-user post-handshake byte budget
- ✅ Proof-of-work tunable gate（0/8/16/24 difficulty）
- ✅ **NEW (本次 commit)**：所有 CONNECTION_CLOSE 走 NO_ERROR/empty reason，消除主動探測重試的分類信號
- ❌ 對「相同 cover-URL 被探測 N 次」沒有時間維度的 anomaly tracking
- ❌ 沒有 **decoy cover 多輪換** —— 我們的 cover_endpoint 是靜態配置

**TODO**：
1. **Cover-endpoint pool 輪換**（M3）：`cover_endpoints: [...]`，每次 cover-forward 從池中隨機挑，避免 GFW 探測到單一 cover-URL 反覆出現。
2. **Probe-anomaly detector**：server side 統計「相同 src_ip 在 N 分鐘內連續觸發 cover-forward」的次數，超閾值寫 metrics + 可選封 IP。
3. **β profile 同樣納入 cover 機制**：目前 β 沒有 cover-forward path（README 已標）。研究在 QUIC 失敗握手後 fallback 到一個真實的 H3 cover server 是否可行。

---

### 主線 5：UDP / QUIC 全國級節流（throttling）

**WHAT**

GFW 開始對所有 UDP 流量（不限 SNI）做頻寬整形（traffic shaping），對識別為 QUIC 的尤其嚴重。Hysteria2 / TUIC 在 2025 還能跑滿頻寬，到 2026 Q1 報告大量速度退化（[saciwor 2026](https://medium.com/@saciwor949/...)、[greatfirewallguide.com/lab/hysteria2](https://greatfirewallguide.com/lab/hysteria2)）。

**WHEN**：2025 Q4 開始零星報告；2026 Q1 普遍化；2026 Q2（4-5 月）報告高峰期 UDP 幾乎不可用。

**WHY 對我們致命**

β profile 是純 QUIC，被節流就速度崩盤。**我們聲稱「超越 Hy2/TUIC5」必須在 UDP 被節流的場景下也成立**。

**Proteus 當前覆蓋**：
- ✅ α profile（TCP+TLS 1.3）作為第二碳水化合物 carrier
- ✅ BBR 擁塞控制（β）在輕中度丟包下仍維持
- ❌ 沒有 **carrier 自動切換**：α 慢就切 β，β 被節流就切回 α
- ❌ 沒有 γ profile（MASQUE / H3-over-QUIC tunneling）—— spec §10 列為 M3+

**TODO**：
1. **Carrier 自動 fallback**（M3）：客戶端維護 α + β 雙 carrier，週期測 throughput，自動選快的。配置：`carrier: auto` vs `carrier: alpha-only` / `carrier: beta-only`。
2. **γ profile (MASQUE)**（M3+，spec §10.3）：H3-tunneled，UDP 被節流時看起來是合法的 H3 流量。
3. **Throughput probe-and-adapt**：客戶端每 N 秒測一次當前 carrier 的有效頻寬，drop 超 50% 即觸發 carrier switch。

---

### 主線 6：DoH / DoT 識別

**WHAT**

GFW 已能「精確識別」境外 DoH 伺服器連線（[Q2 2026 GFW Update](https://sunsetbrowser.app/blog/china-gfw-update-2026-q2-en)），不只是封 1.1.1.1 IP，而是看 HTTPS 流量裡的 DoH POST pattern。

**WHEN**：2026 Q1 開始有零星報告，Q2 進入規模化部署。

**WHY 對我們致命**

如果 Proteus 客戶端用 DoH 解析 server_endpoint，DoH 被識別 → 客戶端啟動就失敗。這影響 **bootstrap 過程**，不是 in-session 流量。

**Proteus 當前覆蓋**：
- ❌ 沒有對 DNS bootstrap 的明確規範
- ❌ `proteus-client run` 直接交給作業系統的 DNS resolver

**TODO**：
1. **配置選項 `bootstrap_dns:`**：支援 `system` / `doh: <url>` / `dot: <addr>` / `direct_ip: 198.51.100.42`（推薦：用 IP 直連跳過 DNS）。
2. **文檔強烈推薦 direct_ip 模式**：把 VPS IP 直接寫進 client.yaml，不靠 DNS。
3. **`proteus-client validate` 檢查**：警告使用了 DoH/DoT 的配置「可能被 GFW 識別」。

---

### 主線 7：「全加密流量」啟發式檢測（Censorship.AI / Wu et al. USENIX 23 → 仍在演進）

**WHAT**

GFW 用 5 條啟發式規則找「看起來是加密流量但不像 TLS/SSH/HTTP」的連線，這是 [Wu et al. USENIX Sec '23](https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf) 揭露的。2026 還在用，且閾值有調整：

| 規則 | 判定 | 規避 |
|---|---|---|
| 1 | 不可印字元 ≥ 70% | 前面塞 ≥ 6 字節可印字元 |
| 2 | 匹配 `\x16\x03[\x01-\x09]`/HTTP verb/`SSH-` 即放行 | 偽裝成 TLS/HTTP/SSH 前綴 |
| 3 | 前 6 字節都可印 → 放行 | 簡單前綴技巧 |
| 4 | 必須完整 3-way handshake | 與正常 TCP 一致即可 |
| 5 | 40 個特定單字節 payload 觸發封鎖 | 避開這些字節 |

**WHY 對我們致命**

α profile 是 TLS 1.3，第一字節 `\x16\x03\x03`（規則 2 放行）→ 不會觸發。**β profile 是 QUIC，UDP first byte 由 QUIC 長 header 決定**：

剛好我們在 commit `5aedb61` 已把 β 的 prefix-noise 第 0 字節調整為「像 short-header QUIC」。但 **prefix-noise 本身仍可能觸發全加密啟發式**（16 個隨機字節，全不可印的機率高）。

**Proteus 當前覆蓋**：
- ✅ α profile 第一字節滿足規則 2（TLS marker），規則 1/3 不適用
- ⚠️ β profile prefix-noise：commit `5aedb61` 已塑形第 0 字節，但 1-15 是純隨機。需要驗證是否觸發規則 1（70% 不可印）
- ⚠️ QUIC Initial 本身 first 6 bytes 通常不可印

**TODO**：
1. **β prefix-noise 規則 1 防禦**（小修）：把 16 字節 prefix-noise 改成「前 6 字節是合法 ASCII 可印字元 + 後 10 字節隨機」，同時符合「像 short-header QUIC」（重新平衡 byte 0 的兩個約束）。
2. **新增 wire 測試**：`quic_prefix_noise_printable_ratio.rs` —— assert prefix-noise 通過 GFW 全加密啟發式。
3. **Spec §5.9 補充**：明確記錄 prefix-noise 要同時滿足 USENIX 25 #2 + USENIX 23 全加密規則。

---

## Proteus 2026 GFW 覆蓋矩陣（總表）

| 對抗向量 | 覆蓋 | Roadmap 位置 |
|---|---|---|
| Tiangou 商用 DPI（共享黑名單）| ⚠️ 部分 | TODO: IP preflight tool |
| Tiangou ML 行為分析 | ✅ cell-split + heartbeats | — |
| uTLS bit-perfect ClientHello | ❌ | M3（README ❌ 已標）|
| 2026-04 中轉節點拔線 | ✅ 設計上免疫（直連架構）| TODO: deployment doc + multi-VPS HA |
| QUIC SNI 審查 (USENIX 25 #1) | ✅ source-port walk | — |
| QUIC SNI 審查 (USENIX 25 #2) | ✅ prefix-noise | — |
| QUIC SNI 審查 (USENIX 25 #4) | ✅ migration API | — |
| ECH（SNI 加密）| ❌ | **P0 升級到 M3** (spec §7.4) |
| Active probing（請求層）| ✅ cover-server splice | — |
| Active probing（時序層）| ⚠️ 部分 | TODO: cover pool + anomaly detector |
| CONNECTION_CLOSE 信號 | ✅ NO_ERROR/empty (本 commit 已 lock-in) | — |
| 應用層 probe（cover URL 反覆探測）| ❌ | TODO: cover_endpoints pool |
| IP 範圍預封 | ❌ | TODO: preflight tool + 文檔警告 |
| UDP/QUIC throttling | ⚠️ α 可用，β 沒 fallback | TODO: carrier auto-switch (M3) |
| γ profile (MASQUE) | ❌ | M3+ (spec §10.3) |
| DoH/DoT 識別（bootstrap）| ❌ | TODO: `bootstrap_dns:` 配置 |
| 全加密啟發式（規則 1: 不可印 70%）| ⚠️ β prefix-noise 風險 | TODO: 調整 prefix-noise 前 6 字節 |
| 全加密啟發式（規則 2: TLS/HTTP/SSH 前綴）| ✅ α 自然滿足 | — |
| Post-quantum store-now-decrypt-later | ✅ ML-KEM-768 hybrid | — |
| Forward secrecy / 4 MiB ratchet | ✅ | — |

## Roadmap 優先級排序（基於上述分析）

**P0（必須在「上線生產環境」前完成）**：

1. **ECH 集成**（主線 3） —— 沒有 ECH 等於 SNI 公開，所有 wire-level trick 都治標
2. **`proteus-server preflight --check-ip-reputation`**（主線 1 + 4）—— 不檢查就讓 operator 拿被封 IP 上線等於送死
3. **`bootstrap_dns: direct_ip`**（主線 6） —— DoH 識別讓客戶端 bootstrap 失敗
4. **β prefix-noise 調整前 6 字節為可印**（主線 7） —— 避免 USENIX 23 規則 1 觸發
5. **`deploy/README.md` topology 警告**（主線 2）—— operator 教育 + 反中轉模型

**P1（M3 前需完成）**：

6. **uTLS bit-perfect ClientHello**（主線 1） —— 唯一還比 Reality 弱的點
7. **Cover-endpoint pool 輪換**（主線 4） —— 對抗時序型主動探測
8. **Carrier auto-switch (α↔β)**（主線 5） —— UDP throttling fallback
9. **Multi-VPS HA 客戶端**（主線 2） —— 單點故障消除

**P2（M3+，長期）**：

10. **γ profile (MASQUE)** —— 終極 UDP throttling 防禦
11. **β profile cover-forward** —— β 對 active probing 的盲區
12. **Multipath QUIC**（spec §10.4） —— 性能 + HA 雙贏

---

## 與大綱的關聯

- **威脅模型升級**：Part 11.3「對手分類學」需新增 Tier-1.5「商用迭代型 DPI（Tiangou-class）」，介於原本的「靜態 GFW」和「未來自適應 AI GFW」之間
- **設計取捨**：Part 11.5「ECH binding」必須從可選升為必須
- **既有課程回顧**：
  - [Part 9.x USENIX 25 QUIC SNI](../lessons/part-9-gfw-research/)（如已寫過）—— 應在最後 backfill 一節「2026-04 節點死亡實況」
  - [Part 4.x TLS 1.3 ECH](../lessons/part-4-tls-quic/)（未寫）—— 必須在 11.5 引用前完成
- **新需求**：寫一篇 Part 9.X「2026 Q1-Q2 GFW 攻勢實況」lesson，把這份 Q&A 升級為正式研究筆記

## 一手來源（要 fetch 進 notes/papers/）

| 來源 | 類型 | Action |
|---|---|---|
| InterSecLab "The Internet Coup" 76p | Geedge 技術分析 | TODO: fetch + precis |
| Amnesty Pakistan 102p (ASA33/0206/2025) | Geedge 部署證據 | TODO: fetch + precis |
| Zohaib et al. USENIX Sec '25 (QUIC SNI) | 已 fetch | ✅ [notes/papers/zohaib-quic-sni-usenix25.md](../notes/papers/zohaib-quic-sni-usenix25.md) |
| Wu et al. USENIX Sec '23 (全加密啟發式) | 老論文但仍 active | TODO: 確認是否已有 precis |
| GFW.report 2025-08-20 port 443 | 已有 precis | ✅ [notes/gfw/2025-08-20-port443-rst-incident.md](../notes/gfw/2025-08-20-port443-rst-incident.md) |
| GFW.report 2025-09-15 Geedge analysis | 二手指針 | ✅ [notes/gfw/2025-09-11-geedge-mesa-leak.md](../notes/gfw/2025-09-11-geedge-mesa-leak.md) |
| HRC 2025-07-23 X post (主動購買訂閱) | 一手新聞 | 已歸檔在本 Q&A |
| RelyVPN 2026-04 crackdown 報告 | 二手新聞 | 已歸檔在本 Q&A |
| net4people/bbs #519 (Geedge 持續追蹤) | 社群討論 | bookmark + 定期回看 |

## 結論

GFW 從 2025 Q3 → 2026 Q2 的攻勢核心不是「新發明的算法」，而是 **工業化 + 商品化**：
- 自家 GFW 軟體出口 → 持續迭代預算
- 跨部署黑名單 → 攻擊面從「協議」擴到「IP 信譽」
- 物理拔線 → 攻擊面從「網路」擴到「IDC + 運營商配合」
- ML 行為分析 → 攻擊面從「簽名」擴到「統計分佈」

對抗策略不能再是「設計一個完美協議」，必須是 **完美協議 + 健康 IP 預檢 + 部署拓撲規範 + 自動 carrier 切換 + ECH bootstrap 隱藏 + 持續追蹤 GFW.report**。

Proteus 的當前位置：協議層已強於 Reality + Hy2/TUIC5；**剩下的 gap 全是工程化 + 部署**。上面 5 條 P0 完成後可以說「上線生產穩定」，11 條全完成可以說「2026 SOTA」。
