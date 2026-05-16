# How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic
**Venue / Year**: USENIX Security 2023
**Authors**: Mingshi Wu (GFW Report), Jackson Sippe (CU Boulder), Danesh Sivakumar (UMD), Jack Burg (UMD), Peter Anderson (independent), Xiaokang Wang (V2Ray Project), Kevin Bock (UMD), Amir Houmansadr (UMass Amherst), Dave Levin (UMD), Eric Wustrow (CU Boulder)
**Read on**: 2026-05-16 (in lessons 7.3, 7.13, 9.3)
**Status**: full PDF (`assets/papers/usenix-2023-wu-fep.pdf`, 11 pp.) — downloaded from USENIX open-access mirror
**One-line**: 2021/11 起 GFW 部署的純被動「全加密協議 (FEP)」偵測系統，被五條粗糙 heuristic 還原——證明「look like nothing」這條 SS/VMess/Obfs4 的核心思路已經破產。

## Problem
2021 年 11 月 6 日中國境內的 Shadowsocks、VMess、Outline 同時被大規模封——而且不是過去常見的 active probing。社群急問：GFW 怎麼純被動就把 FEP 從正常流量分出？這篇用 6 個月的測量資料逆向出答案。

## Contribution
1. 還原 GFW 的 FEP 分類規則：用「白名單型」exemption 邏輯（命中任一條就放行，否則封）。
2. 量化 collateral damage：在 CU Boulder 1.7B 連線上模擬，誤封率 ~0.6%。
3. 觀察 GFW 用 IP 範圍（只掃 ~26% 連線，主要是熱門 VPS 機房）+ 機率封鎖（~26.3%）來把實際誤封壓到 ~0.04%。
4. 證明 passive FEP detector 與 2019 起的 active probing system 是兩套獨立系統，但用相同 traffic-analysis algorithm。
5. 提出五個 circumvention 補丁（payload prefix、protocol mimicry 等），已部署於 SS-rust、SS-android、V2Ray、Outline、Lantern、Psiphon、Conjure。

## Method (just enough to reproduce mentally)
從 11 台中國境內 VPS（TencentCloud Beijing × 10、AlibabaCloud Beijing × 1）對 4 台 DigitalOcean SFO + 2 台 CU Boulder 跑 controlled probes，掃 byte-pattern 空間找哪些 first-packet payload 會被封 180 秒、哪些不會，反推規則。

**五條 exemption（命中任一即放行）**：
- **Ex1（熵）**：first TCP payload 的 popcount/byte 平均 ≤ 3.4 或 ≥ 4.6 → 放行（隨機 ≈ 4.0）。
- **Ex2（前 6 byte 全可印）**：bytes[0..5] 都在 0x20–0x7E → 放行（HTTP verbs、SSH banner 等）。
- **Ex3（過半可印）**：>50% byte 在 ASCII 可印範圍 → 放行。
- **Ex4（連續可印 run）**：>20 個連續 byte 全為 ASCII 可印 → 放行。
- **Ex5（已知協議指紋）**：前幾 byte 匹配 TLS（`\x16-\x17 \x03 \x00-\x09`）或 HTTP verb + space → 放行。

**封鎖行為**：只看 client→server 第一個 data packet（不重組 flow）；只看 TCP（UDP 不影響，QUIC 暫時免疫）；觸發後同 (clientIP, serverIP, serverPort) 三元組封 180 秒；只對熱門 VPS 機房 IP 段啟動 (~26%)；觸發後以 ~26.3% 機率封。

## Results
- 五條規則覆蓋 99.4% 正常流量 → 算法層面誤封 ~0.6%。
- 加上 IP 範圍 + 機率，實測 collateral damage ~0.04%。
- UDP / QUIC 完全不受此 system 影響。
- 修補後（payload prefix 補 ASCII / TLS header）SS、V2Ray 在 2022/01–2023/02 持續可用。

## Limitations / what they don't solve
- 黑盒推斷，未必窮盡 GFW 真實邏輯。
- 觀測窗 2021/11–2023/02，GFW 持續演化，2024+ 結論可能過時。
- 沒測試 ML-based detection、flow reassembly、多 packet 聯合分析。
- 沒涵蓋 IP 範圍以外的場景；若 GFW 擴大掃描，補丁可能失效。

## How it informs our protocol design
- G6 必須**每一條** exemption 都過（OR-of-exemptions 邏輯，只要被任何一條判為「不放行」就封）。
- 最低成本的滿足法：偽裝 TLS 過 Ex5——這是 Trojan / VLESS+REALITY 在工程上勝出的根本原因。
- TCP 為主的協議（VLESS、Trojan）必須在 Part 11.5 spec 強制 first packet TLS-like；UDP/QUIC（Hysteria2、TUIC）暫安全但不能假設長期。
- Probabilistic blocking + IP range 啟示：部署在 CDN IP 段比 VPS 機房 IP 段安全得多，這應反映在 Part 12 evaluation 的部署矩陣。
- GFW 不重組 flow → 「first packet 偽裝、後續自由」是當下可用設計，但 Part 11 威脅模型必須包含「對手升級到看前 N packet」。
- Active probing 與 passive 共用 algorithm → 過 passive 大概率也過 active probing。

## Open questions
- GFW 為什麼不 reassemble flow——技術瓶頸還是策略選擇？
- ML-based FEP detection 何時部署？（G7 對手）
- HTTP/3 (QUIC) 是否會被 UDP 側其他 system 封？Hysteria2 在中國境內的封鎖事件值得長期追蹤。
- 對手升級到「TLS handshake completion check」後，偽裝 TLS 還夠嗎？（REALITY 的存在預期了這個升級。）
- 為何 GFW 接受 26.3% 機率封？運算瓶頸還是政治容忍度的設計選擇？

## References worth following
- Alice et al., USENIX Security 2020 — GFW 對 SS 的 active probing 系統分析（本篇 [5]）。
- Frolov & Wustrow, NDSS 2019 — *The use of TLS in Censorship Circumvention*。
- Houmansadr et al., S&P 2013 — *The Parrot is Dead*（mimicry 失敗論）。
- Frolov et al., CCS 2019 — *Conjure*。
- Bock et al., CCS 2019/2020 — *Geneva* GA 找 evasion。
- GFW Report (https://gfw.report/) — 本論文與後續更新的 primary source。
- 本篇 §8 Customizable Payload Prefixes — SS-rust / SS-android 已落地的具體規避實作。

## 跨札記連結
- 完整版精讀札記見 [`wu-fep-detection.md`](./wu-fep-detection.md)（同一篇論文，含 Tschantz / Khattak 對話與 G2→G3/G4 演化分析）。本檔為簡版索引，給 lessons 7.3 / 7.13 / 9.3 引用用。
