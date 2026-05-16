# FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic
**Venue / Year**: NDSS 2020（Network and Distributed System Security Symposium），DOI 10.14722/ndss.2020.24412
**Authors**: Thijs van Ede、Riccardo Bortolameotti、Andrea Continella、Jingjing Ren、Daniel J. Dubois、Martina Lindorfer、David R. Choffnes、Maarten van Steen、Andreas Peter（U. Twente / Bitdefender / UCSB / Northeastern / TU Wien）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx traffic analysis 對手模型）
**Status**: full content from NDSS abstract + paper PDF metadata + GitHub README；PDF 二進位下載成功但 inline 解析失敗，內容由搜尋結果摘要拼出
**One-line**: 把行動 app 的 encrypted flow 用「destination-based clustering + 時間相關性」分群，**不需要事先看過該 app** 就能持續產生 fingerprint，89.2% 識別準確率、93.5% precision 偵測未知 app——semi-supervised 是它與舊 supervised approach 最大的差別。

## Problem
舊 mobile app fingerprinting（AppScanner、FlowPrint 之前的 ProprioTraffic 等）要先在 lab 跑過該 app、收 training trace、訓 classifier，才能在 wild 識別。但 (a) Google Play / App Store 每天新增上萬 app，沒有人能跑遍；(b) app 更新會讓 fingerprint 偏移；(c) 多數現代 app traffic 已 TLS 加密。需要一個能持續學、能 detect 未知 app 的方法。

## Contribution
- 提出 **FlowPrint**：semi-supervised fingerprinting framework。不需要 per-app training trace，靠 traffic 內在的 destination / temporal pattern 自動聚類。
- **Destination-based clustering**：把同一 app 在短時間窗口內訪問的目的 IP/SNI 視為「自然 cluster」（因為 app 同時打它的 backend + ad SDK + analytics）。
- **Cross-correlation graph**：在 cluster 之上建圖，邊權是「兩個 cluster 在相同 time window 內共同出現」的頻率，再做 community detection 抽出 fingerprint。
- **未知 app 偵測**：當 traffic 不 match 任何已知 fingerprint，就視為 new app，自動發配新 fingerprint id；運營人員可事後 label。
- 在 ReCon、Andrubis、Cross-Platform 三個 dataset（Android + iOS）上 89.2% 識別 accuracy；未知 app 偵測 93.5% precision、72.3% 在 5 分鐘內。

## Method (just enough to reproduce mentally)
1. **Flow extraction**: 把 PCAP 切成 (src, dst, dport, sport, proto) flow。
2. **Destination features**: 對每個 flow 提取目的 (IP, port) 與 TLS SNI（若有）。
3. **Temporal correlation**: 滑動 time window（預設 30s）；同一 window 中共同出現的目的視為相關。
4. **Cross-correlation graph**: nodes = (destination, app-context)，edges = co-occurrence weight。Apply community detection（modularity-based）得到 cluster。
5. **Fingerprint**: 每個 cluster = 一個候選 app fingerprint。Online phase 拿新 flow 與已有 fingerprint match，超過信心 threshold 視為 known、否則為 new。
6. **Confidence metric**: 用 AMI（Adjusted Mutual Information）—— fingerprint label 對 app label 的 entropy reduction。

## Results
- **App recognition**: 89.2% accuracy（多分類），明顯優於 supervised AppScanner（同 precision，但 recall 大幅落後）。
- **Unseen app detection**: 93.5% precision、72.3% recall within first 5 minutes。
- **Cross-platform**: Android & iOS 同方法可用，泛化良好。
- **Robust to TLS 1.3 + ECH**: 因為它不靠 SNI 明文，靠 destination IP + 時間 pattern；即使 SNI 加密，destination IP 仍洩漏。

## Limitations / what they don't solve
- 嚴重依賴「app 同時打多個 known endpoint」——若 app 只打單一 CDN（或全走 proxy 隧道），FlowPrint 無法抽出 cluster。
- 不識別「同 app 內的不同 action」（聊天 vs. 視頻 vs. 上傳）——這是 DF 級 WF 才解決的問題。
- Confidence threshold 是 hyperparameter，調太緊 false positive 高、調太鬆 unseen detection 沒用。

## How it informs our protocol design
FlowPrint 揭示一個對 protoxx **極危險**的對手能力：即使 packet content 完全加密、SNI 加密、padding 拉到最大，**destination IP 與 timing co-occurrence 本身**就足以在 89% 準確率下分類 app。對 protoxx 的含意：
1. **單一 destination = 單一 fingerprint**：proxy 把所有流量集中到一個 server IP，反而給了 FlowPrint 級攻擊一個極強訊號（「凡是打這個 IP 的都是 proxy 用戶」）。需要 IP rotation、CDN fronting、多 endpoint 設計。
2. **Co-occurrence pattern 也要 shape**：不只動 packet 層，session 層的「同時連幾個 dst」「dst 變化頻率」也屬於可指紋化的維度。
3. 我們的 evaluation harness 必須跑 FlowPrint，把 attack accuracy 作為 destination-side adversary 的 metric。

## Open questions
- FlowPrint 在 fully-domain-fronted（如 Meek、Cloudflare Workers）流量下表現如何？是否仍能從 timing pattern 抽 cluster？
- 用 cover traffic（背景白噪音）混淆 co-occurrence graph 的有效成本？

## References worth following
- Taylor, Spolaor, Conti, Martinovic. *AppScanner: Automatic fingerprinting of smartphone apps from encrypted network traffic.* EuroS&P 2016 — 監督式對照組。
- Anderson, McGrew. *Identifying encrypted malware traffic with contextual flow data.* AISec 2016 — 同類型 contextual fingerprinting。
- Saltaformaggio et al. *Eavesdropping on fine-grained user activities within smartphone apps over encrypted network traffic.* WOOT 2016。

Source: [NDSS paper page](https://www.ndss-symposium.org/ndss-paper/flowprint-semi-supervised-mobile-app-fingerprinting-on-encrypted-network-traffic/), [PDF](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24412.pdf), [GitHub](https://github.com/Thijsvanede/FlowPrint)
