# Detecting Probe-resistant Proxies

**Venue / Year**: NDSS 2020
**Authors**: Sergey Frolov, Jack Wampler, Eric Wustrow (University of Colorado Boulder)
**Read on**: 2026-05-16 (in lessons 7.10–7.12)
**Status**: full PDF
**One-line**: 「永遠沉默」本身就是指紋——對 obfs4 / Shadowsocks / Lampshade / MTProto / OSSH 用幾個基本協議 probe + 量測 close threshold 與 timeout，就能以 < 0.001 % FPR 抓出大多數 probe-resistant proxy。

## Problem

第二代翻牆協議（obfs4、Shadowsocks AEAD、Lampshade、MTProto、Obfuscated SSH）的設計假設是：「對手無法構造合法 handshake → server 不回應 → 審查者區分不出 proxy 和普通沉默服務。」此論文質疑此假設：在真實 Internet 上「對所有 probe 都不回任何 byte」其實**極罕見**，本身就是高度識別性指紋。

## Contribution

1. 系統化定義 **close threshold**（FIN threshold / RST threshold）這個全新的 application-level fingerprint 維度——伺服器在 read 多少 bytes 後選擇 close。先前文獻只討論 OS-level TCP 指紋。
2. 對 5 個主流 probe-resistant 協議建決策樹分類器，於 433 K（passive tap）+ 1.5 M（ZMap）endpoints 驗證，**FPR < 0.001 %**（MTProto 除外）。
3. 與 Psiphon、Tor obfs4、Outline、Lantern 等專案 coordinated disclosure，多數已 patch（2019/05–10）。
4. 驗證 MTProto 的「永不 timeout」策略是當前最難偵測者，但仍有 0.02 %–0.56 % collision，可作為其他協議借鏡（→ 後來 REALITY、Hysteria 都採用 fallback-to-real-server 策略，比沉默更隱蔽）。

## Method (just enough to reproduce mentally)

**Probes** (TCP only)：
- 協議 probe：HTTP/1.1 GET、TLS ClientHello (Chromium 71)、Modbus、S7、DNS AXFR、STUN（手動補加）。
- 隨機 bytes（多種長度，用於量 close threshold）。
- Empty probe（不送資料，純等對方先說話）。

**特徵向量**（每個 endpoint × probe）：
- 是否回 application data。
- close 方式：FIN / RST / TIMEOUT。
- close 時間（500 ms 容差判定 probe-indifferent）。
- close threshold：用二分搜對隨機 bytes 量 server 在收到第 N byte 後 close，N_FIN vs N_RST。

**Datasets**：
- **Tap**：Colorado 大學 10 Gbps router netflow，3 天蒐集 550 K endpoints，433 K 接受 follow-up 連線。
- **ZMap**：1.5 M endpoints（全 port 全網段隨機 SYN scan）。
- **Proxy ground truth**：BridgeDB（obfs4 ×20+）、developers 提供（Lampshade ×3、OSSH ×3）、Telegram app（MTProto ×3）、自架（Shadowsocks）。

對每協議手刻決策樹（timeout 範圍、threshold 區間、FIN/RST 模式）。

## Results

| Protocol | Close threshold | Timeout | Tap FP | ZMap FP |
|---|---|---|---|---|
| obfs4 | 8–16 KB（隨機）| 60–180 s | 2 / 433k | 0 |
| Lampshade | 256 B | 90 / 135 s | 0 | 1 |
| Shadowsocks (Outline / Python AEAD) | 50 B | configurable | 0 | 8 |
| MTProto | — (永不 close) | — | 3144 | 296 |
| OSSH | 24 B | 30 s | 8（其中 7 經 Psiphon 確認真為 OSSH server）| 0 |

obfs4 的 RST threshold 表現出 mod-1448 規律（buffer size 1448 B），是極獨特指紋，幾乎無誤判。

## Limitations / what they don't solve

- 只研究 TCP，未涵蓋 UDP-based proxy（QUIC、WireGuard、Hysteria）。
- 只測 5 個協議，REALITY / Snowflake / TUIC 不在其列（時序在前）。
- Vantage point 是 US 大學網路；不同地理位置的 endpoint 分布可能不同。
- MTProto 的 3 K 誤判沒做手動驗證，無法確認 false positive 還是 unknown true positive。
- 假設 censor 能對任意 IP 主動 probe；不適用對方有 firewall 阻擋來自審查者 ASN 的場景。
- Base rate 問題：FPR 0.001 % × 全網 IP 仍是巨量，是否 deployable 看審查者願承擔多少 collateral damage。

## How it informs our protocol design

對 Proteus 的核心啟示：**「不回應」是最差的策略**。所有後 2020 年的高品質 probe-resistant 協議（REALITY、ShadowTLS、Hysteria2 obfs、TUIC v5）都改採**fallback-to-real-server**：handshake 失敗時把連線透明轉發到一個合法服務（如真實網站、SSH server），讓 censor 看到真實的應用回應。這是本論文間接催生的設計範式轉移。

具體在 Proteus 設計需確保：
1. Handshake 失敗路徑必須產生**與我們的 fallback 目標 server 在 byte/timing 上不可區分**的回應（這比沉默強，但若 fallback 路徑的 timeout / threshold 與真實服務不同，仍可被本論文方法抓出）。
2. 不要有獨特的 close threshold（avoid magic numbers like 50 / 24 / 256）。
3. 量測自家實作在隨機 bytes 下的 FIN/RST behavior，與 fallback 目標對照測試（即把 Frolov 的 probe 套件當 CI test）。
4. timeout 隨機化要分布在合理區間（與真實 nginx/apache idle timeout 重疊），不要寫死成 30/60/90 這類舊典型值。

## Open questions

- UDP-based protocol（QUIC / Hysteria2）有沒有類似的 close-threshold-equivalent 指紋？（目前無系統研究，是 Part 8 / Part 12 的潛在貢獻點。）
- Fallback-to-real-server 策略本身能否被 timing side-channel 區分（fallback 經過 proxy 比直連真站多一跳延遲）？Wu et al. USENIX Security 2023 部分回答（FEP detection），但仍開放。
- 機器學習 probe selection（自動從 ISP tap 學 probe 模板）是否能進一步降低 FPR？論文 §VIII.B 提及但未實作。

## References worth following

- Wang et al., 「Seeing through Network-Protocol Obfuscation」, CCS 2015 — 熵測試 passive detection，本論文反覆引用。
- Houmansadr et al., 「The Parrot is Dead」, S&P 2013 — Protocol Mimicry 為何失敗的奠基論文（→ `notes/papers/houmansadr-parrot-is-dead.md`）。
- Ensafi et al., 「Examining How the Great Firewall Discovers Hidden Circumvention Servers」, IMC 2015 — GFW 主動探測架構實測（→ `notes/papers/ensafi-gfw-probing.md`）。
- Wu et al., 「How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic」, USENIX Security 2023 — 後續工作，把 entropy-based detection 升級到實戰部署的 GFW（→ `notes/papers/wu-fep-2023.md`、`wu-fep-detection.md`）。
- Fifield 「David Fifield's notes on circumvention」 blog — 推薦的 acknowledgements 之一，背景閱讀。
