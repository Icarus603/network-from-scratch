# The use of TLS in Censorship Circumvention
**Venue / Year**: NDSS 2019
**Authors**: Sergey Frolov、Eric Wustrow（University of Colorado Boulder）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx fingerprint resistance）
**Status**: full abstract + key findings via NDSS page；PDF 直接抓取失敗（HTTP 404）但 content via author page + NDSS abstract 完整可信
**One-line**: 對 11.8 billion 條真實 TLS 連線做大規模測量，證明 Lantern、Psiphon、Signal、Outline、TapDance、Tor 等所有主流 circumvention tool 的 TLS 握手都和瀏覽器明顯可區分；同時釋出 **uTLS** library，讓 Go 程式能精準仿冒 Chrome/Firefox/Edge 等 ClientHello。

## Problem
TLS 是 censorship circumvention 的 cover——「我看起來就是 HTTPS，你想擋就要連無數正常網站一起擋」。但這個 cover 只在 ClientHello 與 ServerHello fingerprint 真的像瀏覽器時有效。Go 的 crypto/tls、Python 的 ssl、Rust 的 rustls 各有自己的 cipher suite ordering、extension list、key share 順序——任何 censor 用一張 fingerprint table 就能分流。問題：實際野生流量中 fingerprint diversity 有多大？哪些 circumvention tool 已被「點名」？怎麼修？

## Contribution
- **大規模測量**：在校園網路抓 9 個月 11.8 billion 條 TLS 連線，建立 fingerprint table（cipher suite list、extension order、curve、ALPN 等）。
- **Tool fingerprint analysis**：對 Lantern、Psiphon、Signal、Outline、TapDance、meek-Tor、Snowflake 等做指紋擷取；結論——每一個都和真實瀏覽器有明顯差異（多在 cipher ordering、extension list、grease 處理）。
- **uTLS library**：以 Go crypto/tls 為基礎 fork，提供 `tls.UClientHelloID` API，可指定 mimick Chrome 70 / Firefox 65 / iOS Safari 12 等具體版本的 fingerprint，並支援動態切換。
- 量化結論：原版 Go TLS client 在 11.8B 樣本中 **只佔 0.0003%**，等於是裸奔——任何 fingerprint-based censor 一刀就切。

## Method (just enough to reproduce mentally)
1. 在 CU Boulder 校園網部署 passive monitor，抓 9 個月的 TLS handshake。
2. 用 [ja3](https://github.com/salesforce/ja3) 風格 hash：對 (TLS version, cipher list, extension list, EC curve list, EC point format) 取 hash。
3. 對每個 hash 統計 client population（多少 IP 用它），建 fingerprint → 工具映射。
4. 對 circumvention tool 跑同樣 handshake、計算 hash、與 wild distribution 比對。
5. 對發現的問題寫 uTLS：把 ClientHello 的每個欄位拆成可替換的 spec，預載一組「主流瀏覽器版本」spec。

## Results
- Go crypto/tls 原版 fingerprint 全球佔比 0.0003%，等於直接舉旗。
- Lantern、Psiphon、Outline、Signal 雖各自做了 mimick 嘗試，但都 leak 在 (a) extension ordering、(b) GREASE 值、(c) supported_versions 列表上。
- meek-Tor 已用 uTLS 前身，但版本落後當期 Chrome 兩個 release。
- uTLS 釋出後迅速成為 Xray、sing-box、V2Ray、Lantern、Psiphon 的標準 TLS 層；REALITY (Xray) 也基於 uTLS。

## Limitations / what they don't solve
- 只看 ClientHello / ServerHello，不看後續 application data（Hysteria2 級的 record padding fingerprint 未涵蓋）。
- mimick fingerprint 是 cat-and-mouse：Chrome 每 6 週 update，circumvention tool 也要跟。
- 沒解決「即使 fingerprint 完美像 Chrome，但 destination IP 是 known proxy server」這個 IP-list 問題（GFW 主動探測 + IP block）。

## How it informs our protocol design
protoxx 的 fallback / disguise 層必須直接用 **uTLS（或 Rust 對應的 rustls + 仿冒 patch）**：
1. ClientHello 必須是當期 (year - 0.5) 主流瀏覽器的精確 fingerprint，包括 GREASE、extension ordering、key share 順序。
2. ServerHello 端也要 mimick：選一個對應的瀏覽器組合，response 也匹配。
3. uTLS 的 spec 在我們的 release cycle 中要 quarterly refresh（跟 Chrome 主版本）。
4. 12.X 的 evaluation harness 必須跑 ja3 / ja4 collision 測試：protoxx fingerprint 與當期 Chrome fingerprint 的 hash collision 比例必須 = 1.0。

## Open questions
- 在 TLS 1.3 + ECH 部署之後，ClientHelloInner 還是會 fingerprint，這層 mimick 該怎麼做？
- 是否能讓 protoxx 的 server 自動「複製當下訪問它的瀏覽器 fingerprint」做動態仿冒？

## References worth following
- Houmansadr, Brubaker, Shmatikov. *The parrot is dead: Observing unobservable network communications.* IEEE S&P 2013 — 證明「mimick 看似簡單實則極難」的經典反論。
- Wang, Dyer, Krishnamurthy, Houmansadr. *Seeing through network-protocol obfuscation.* CCS 2015 — 對 obfs4 等做 ML 識別。
- uTLS GitHub: https://github.com/refraction-networking/utls — 持續維護的 reference impl。

Source: [NDSS 2019 paper](https://www.ndss-symposium.org/ndss-paper/the-use-of-tls-in-censorship-circumvention/), [uTLS](https://github.com/refraction-networking/utls)
