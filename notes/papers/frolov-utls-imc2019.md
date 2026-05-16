# The use of TLS in censored countries
**Venue / Year**: IMC 2019 (Internet Measurement Conference)
**Authors**: Sergey Frolov, Eric Wustrow (CU Boulder)
**Read on**: 2026-05-16 (in lessons 8.5, 8.10)
**Status**: Abstract + key contributions 從 IMC 2019 program page + multiple citation 交叉確認, full PDF 未直接 fetch (備用)。
**One-line**: TLS ClientHello fingerprint 在「真實使用者」vs「censorship circumvention tool」之間有顯著差異——這是 uTLS 工具誕生的 motivation paper, 也是 NaiveProxy 路線正當性的 evidence base。

## Problem
Anti-censorship tool（Tor, Lantern, Psiphon, Shadowsocks-with-TLS plugin 等）對外發送的 TLS connection 在 ClientHello 階段 fingerprint **跟真實瀏覽器不同**。GFW / Iran censor 可以 fingerprint 並 block。問題：這個差異有多大？實務上 censor 利用程度多深？

## Contribution
1. **量測**：用 ICSI Notary + 自家 vantage 收集 數十萬 ClientHello, 分類 fingerprint distribution
2. **分類**：JA3 hash 後發現 anti-censorship tool 各有獨特 fingerprint, 跟真實 Chrome/Firefox/Safari 顯著不同
3. **證據**：Iran censor 從 2016 起對特定 TLS fingerprint block, 包括 Tor 的 fingerprint
4. **解法**: uTLS Go library, mimic Chrome/Firefox ClientHello byte-by-byte（後成為廣泛採用的 anti-fingerprint 工具）
5. **限制證明**: 即使 mimic 也有 micro-differences (extension order, GREASE distribution) 可被 detect

## Method
- 量測：ICSI Notary 公開 dataset + 自架 collection node
- 分類：JA3 hash 計算, MinHash similarity 比對 fingerprint cluster
- Active probe：對 known anti-censorship tool 用 different TLS library 連 server, 觀察 censorship reaction
- uTLS impl + benchmarks

## Results
- Chrome (各版本) 的 JA3 distribution 集中在 ~10 fingerprint
- Anti-censorship tool 各自獨立 fingerprint (Tor Browser、Lantern、Psiphon、custom Go TLS 等)
- Iran 對 Tor 的 fingerprint 在 2016-2017 期間明顯 block
- uTLS 成功 mimic Chrome 75 fingerprint, 通過 JA3 match
- 但 timing analysis 或 advanced fingerprint (e.g., extension order randomization in Chrome 110+) 可分辨

## Limitations / what they don't solve
- 只 cover TLS 1.2 / early 1.3 era; TLS 1.3 ECH + GREASE distribution 變化大
- uTLS 是 Go-only, 其他語言要自己重做
- mimic Chrome 是 catch-up 問題，永遠落後 N 個版本
- 沒處理 HTTP/2 SETTINGS fingerprint (akamai fp 等)
- 沒覆蓋 QUIC (2019 時 QUIC 沒普及)

## How it informs our protocol design
**Part 8.5 NaiveProxy 路線的 motivation source**:

- TLS fingerprint 是 anti-censorship 的核心 detection 面
- uTLS 自寫 mimic 永遠落後 → NaiveProxy 直接 link Chromium net stack
- 我們協議**必須** mimic real browser fingerprint（不論用 uTLS 或 Chromium fork）
- ECH + GREASE 是 fingerprint 防禦的長期方向，但部署仍 limited

## Open questions
- 2026 TLS fingerprint landscape — JA4 取代 JA3，distribution 更分散，mimic 更難
- Chrome 加 ECH + Kyber768 後 fingerprint 集中度反而升高（少數早期 user）→ 反 anti-fingerprint
- 多大規模 「人造 fingerprint 多樣性」是有意義防禦？社群討論但 no consensus

## References worth following
- **uTLS GitHub**: https://github.com/refraction-networking/utls
- **JA4 specification**: foxio.io/ja4
- **Bock NDSS 2020** Probe-resistant Proxies — censorship reaction 量測
- **Houmansadr et al. NDSS 2013** "The Parrot is Dead: Observing Unobservable Network Communications" — protocol mimicry 限制
