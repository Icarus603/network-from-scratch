# How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic

**Venue / Year**: USENIX Security Symposium 2023
**Authors**: Mingshi Wu (GFW Report), Jackson Sippe (CU Boulder), Danesh Sivakumar (UMD), Jack Burg (UMD), Peter Anderson (independent), Xiaokang Wang (V2Ray Project), Kevin Bock (UMD), Amir Houmansadr (UMass Amherst), Dave Levin (UMD), Eric Wustrow (CU Boulder)
**Read on**: 2026-05-14 (in lesson 0.1)
**Status**: full PDF (18 pages) at `assets/papers/usenix-sec-2023-wu-fep-detection.pdf` (read pp. 1–12 in detail; remaining sections cover circumvention strategies, related work, conclusions)
**One-line**: 反向工程 GFW 2021/11 部署的新封鎖系統——用 5 條粗糙但便宜的 heuristic 純被動偵測「全加密協議」（Shadowsocks、VMess、Obfs4），證明 SS 系協議過去十年的核心假設「看起來像隨機就能躲」**已被打破**。

## Problem

過去翻牆協議的主流路線是 **fully encrypted protocol (FEP)**——每個 byte 都加密，目標是 *look like nothing*（看起來什麼都不像）。Shadowsocks、VMess、Obfs4 全走這條路。

**2021 年 11 月 6 日**，中國境內 SS、VMess、Outline 等服務同時被大規模封——而且不是靠 active probing。社群在問：**GFW 怎麼純被動就認出 FEP？**

## Contribution

1. **逆向出 GFW 的偵測規則**：用 5 條 heuristic 區分「可能是 FEP」與「不是」——任何符合 exemption 的就放行，否則封鎖（具體規則見 Method）。
2. **誤封率 0.6%**：在 CU Boulder 校園 1.7B connections 上模擬，發現 GFW 的規則會誤封 0.6% 正常流量——但 **GFW 用 IP 範圍限制（只查 26% 連線到熱門 VPS 機房）+ probabilistic blocking（26.3%）來控制 collateral damage**。
3. **與 active probing 系統並行**：證明這個新 passive system 跟 2019 年起的 active probing system 是兩個獨立但用相同 traffic analysis algorithm 的系統。
4. **5 個 circumvention strategies**：給 SS、V2Ray、Outline、Lantern、Psiphon、Conjure 開發者的修補建議——已在 2022/01–10 部署，至 2023/02 仍有效。

## Method

**5 條 exemption rules**（命中任一即不封）：

1. **Ex1（Entropy）**：第一個 TCP payload 的 popcount/byte（每 byte 1 bit 數平均）**≤ 3.4 或 ≥ 4.6** → 放行。隨機資料 popcount/byte ≈ 4，正常協議因有 zero-padding 或 plaintext header 通常偏離 4。
2. **Ex2（First 6 bytes printable）**：前 6 byte 全是 0x20–0x7e (ASCII 可印字) → 放行（包到 GET / POST / SSH 等明文起頭）。
3. **Ex3（Half printable）**：> 50% byte 是 ASCII 可印 → 放行。
4. **Ex4（Contiguous printable run）**：> 20 連續 byte 是 ASCII 可印 → 放行。
5. **Ex5（Protocol fingerprint）**：前幾 byte 匹配 TLS (`\x16-\x17 \x03 \x00-\x09`) 或 HTTP (verb + space) → 放行。

**封鎖行為**：
- 觸發後封鎖 **180 秒** residual censorship（同 3-tuple client IP + server IP + server port）
- 只 inspect **TCP**，UDP 不影響
- 只 inspect **client→server** 第一個 packet
- 等 **TCP handshake 完成**才看
- 對 200-byte 範圍的 random payload 觸發機率約 26.3%（probabilistic）
- 對特定 VPS 機房 IP 範圍（DigitalOcean、Linode、Alibaba、Constant 等熱門 IP 段）才掃，CDN（Cloudflare、Akamai）不掃

**實驗設置**（Table 1）：6 個月測量 + 1 個月 Internet scan + 3 個月 live traffic + 3 週 active probing 平行實驗。VPS 跑在中國 TencentCloud Beijing（10 台）+ AlibabaCloud Beijing（1 台），對端在 DigitalOcean SFO（4 台）+ CU Boulder（2 台）。

## Results

- **5 條 exemption rules cover** 99.4% 正常流量 → GFW 算法誤封率 ~0.6%
- GFW 真實限縮到 26% IP + 26.3% probability，**進一步降到 ~0.6% × 26% × 26.3% ≈ 0.04% 實際誤封**
- **不影響 UDP**——意味 QUIC 系協議（Hysteria/TUIC）暫時不受此 system 影響
- **不重組 flow**——只看第一個 data packet。給 circumvention 設計留空間

## Limitations / what they don't solve

- 黑盒推斷，未必窮盡 GFW 真實規則
- 觀測在 2021/11–2023/02 之間，**GFW 持續演化**——本篇結論可能在 2024+ 已過時
- 沒覆蓋**未針對 IP 範圍**的場景：如果 GFW 擴大掃描範圍會怎樣？目前不知
- 沒處理**flow reassembly + 多 packet 分析**——若 GFW 升級到看前 N 個 packet，circumvention 策略要重做
- 對**ML-based detection**只測試了基於這 5 規則的 traffic analysis algorithm，沒測試其他可能的 ML 系統

## How it informs our protocol design

**這篇是 G2/G3 世代協議被打的決定性證據**，直接定義了 G6（我們）必須過的 baseline：

1. **G6 必須通過所有 5 條 exemption** — 不是隨便一條，而是**每條都過**，因為 GFW 是 OR-of-exemptions 邏輯
2. **最簡單的滿足方法**：偽裝成 TLS（過 Ex5）——這就是 Trojan/VLESS+REALITY 為什麼勝出的工程理由
3. **TCP 之外**：UDP/QUIC 系暫時不受此 system 影響——這是 Hysteria2/TUIC v5 的暫時優勢，但**不能假設長期成立**
4. **Probabilistic blocking 啟示**：GFW 願意接受誤封率，但用 IP 範圍 + probability 控制 collateral damage——我們協議設計時要假設**部署在熱門 VPS 機房 IP 上**會被優先掃，而 CDN IP 段相對安全
5. **Flow reassembly assumption**：GFW 目前只看 first packet——我們可以**設計成第一個 packet 偽裝、後續 packet 自由**（但要認知 GFW 升級後此假設會破）
6. **Active probing 跟 passive detection 用同一套 algorithm**——意味著只要過了 passive detection，active probing 大概率也過

**對應到 Part 11/12**：
- Part 11.1 威脅模型必須包含「GFW 規則 + 比 GFW 規則嚴格的對手（假設 GFW 會升級）」
- Part 11.5 spec 撰寫時，**第一個 packet 必須**通過 Ex5 (TLS or HTTP fingerprint match)，理由標明此篇
- Part 12.15 抗審查評測要復現本篇的 5 規則 detector，當作 baseline 必過

## Open questions

- GFW 為什麼**不重組 flow**？是技術限制（throughput）還是策略選擇？如果是前者，硬體升級就會破。
- **ML 化的 detection 何時來**？本篇用的全是 deterministic rule，但 ML 需要的算力降低後 GFW 必然會用——這是 G7 世代的對手。
- 為什麼 GFW **probabilistic** blocking？論文猜兩個原因（降低運算 + 降低誤封 collateral damage），但沒實證。
- 本篇沒分析 **HTTP/3 (QUIC)** 是否會被 UDP-side 的某個系統封——Hysteria2 在中國境內的封鎖事件值得追蹤
- 對手能力升級後，**Ex5 偽裝成 TLS** 還夠嗎？需要假設 GFW 會做 TLS handshake completion check（實際上 REALITY 為什麼有意義就是預期這個升級）

## References worth following

- **Alice et al.** (USENIX Sec 2020) — GFW 對 SS 的 active probing 的最早系統分析，本篇引用為 [5]
- **Frolov & Wustrow** *The use of TLS in Censorship Circumvention* (NDSS 2019) — TLS-based circumvention 的指紋問題
- **Houmansadr et al.** *Parrot is Dead* (S&P 2013) — mimicry 失敗證明
- **Conjure** (CCS 2019) — Decoy routing 的 modern 變體
- **GFW Report** ongoing posts — 本論文後續更新都在 https://gfw.report/
- **Bock et al.** *Geneve* — 用 GA 找 evasion 策略
- 本篇 §8 Customizable Payload Prefixes — Shadowsocks-rust、Shadowsocks-android 已部署的具體規避實作

## 跨札記連結

- **與 Tschantz 2016 對話**：Tschantz D2 假設「censor 偏好便宜被動 + active probing」——本篇證實 GFW **真的**偏好便宜被動，但「便宜」的標準包含實時被動全加密偵測（不只是看 IP/SNI）
- **與 Khattak 2016 對話**：本篇對 Khattak 框架的 *Content Obfuscation* 屬性是**毀滅性的**——傳統 SS-AEAD 的 content obfuscation 看似完美（純隨機），但被簡單熵檢測打爆
- **是 G2 → G3/G4 演化的學理基礎**：解釋了為什麼 Trojan（偽裝 HTTPS）和 VLESS+REALITY（借 TLS 握手）必須誕生
