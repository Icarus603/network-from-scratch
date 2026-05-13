# Paper Reading Notes

每讀一篇論文寫一份。檔名用論文短代號 + 年份，例如：
- `gfw-ss-imc20.md` (How China Detects and Blocks Shadowsocks, IMC 2020)
- `bbr-cacm17.md` (BBR: Congestion-Based Congestion Control, CACM 2017)
- `quic-sigcomm17.md` (The QUIC Transport Protocol, SIGCOMM 2017)

## 模板

```markdown
# <Paper title>
**Venue / Year**: USENIX Security / NDSS / SIGCOMM / IMC / CCS / IEEE S&P / PoPETs / IACR ePrint / RFC / arXiv
**Authors**: ...
**Read on**: YYYY-MM-DD (in lesson X.Y)
**One-line**: 一句話總結

## Problem
這篇論文要解決什麼問題？

## Contribution
作者宣稱的核心貢獻（通常 intro 第 5~7 段）

## Method
方法精要（夠你心裡重現，不必 1:1 抄）

## Results
關鍵數據

## Limitations / what they don't solve
作者承認的限制、以及你覺得 reviewer 會 push back 的地方

## How it informs our protocol design
這對我們研究目標（抗審查 + 高速 SOTA）有什麼啟示？

## Open questions
讀完後你還想問的問題（之後做研究時可能會回來找答案）

## References worth following
裡面引用的、值得追下去的論文 / 原始碼 / 標準
```

## 主題分類（之後會用 tag 系統，現在先按 Part 對齊）

- Part 1 網路基礎類論文
- Part 2 高效能 I/O / kernel 網路
- Part 3 密碼學
- Part 4 TLS / QUIC
- Part 6~8 各協議 spec / 設計論文
- Part 9 GFW / 審查研究（最多）
- Part 10 流量分析 / 對抗
- Part 11~12 我們自己論文相關的 related work
