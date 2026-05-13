<div align="center">

# `network-from-scratch`

**從電晶體到 SOTA**

*抗審查 + 高效能代理協議的研究級課程*

<sub>由 [Icarus](https://github.com/Icarus603) 與 Claude 共同建立的長期授課與研究存檔</sub>

<br/>

[![Lessons](https://img.shields.io/badge/lessons-1%20%2F%20150-blue?style=flat-square)](./SYLLABUS.md)
[![Phase](https://img.shields.io/badge/phase-I%20Foundations-orange?style=flat-square)](./SYLLABUS.md)
[![Last Commit](https://img.shields.io/github/last-commit/Icarus603/network-from-scratch?style=flat-square)](https://github.com/Icarus603/network-from-scratch/commits/main)
[![Language](https://img.shields.io/badge/lang-繁體中文-red?style=flat-square)](#)

</div>

---

> **起點** — 能用一鍵腳本在 VPS 上搭機場、能用 Clash Verge Rev 翻牆，**網路理論零基礎**。
> **終點** — 設計並實作一個**新的代理協議**，同時兼具 VLESS+REALITY 的抗審查與 Hysteria2 / TUIC v5 的速度。目標是新 SOTA。

<br/>

## 學習旅程

<table>
<tr>
  <th width="33%" align="center">Phase I</th>
  <th width="33%" align="center">Phase II</th>
  <th width="33%" align="center">Phase III</th>
</tr>
<tr>
  <td align="center"><strong>地基</strong></td>
  <td align="center"><strong>SOTA 解剖</strong></td>
  <td align="center"><strong>設計與實作</strong></td>
</tr>
<tr>
  <td align="center"><sub>6 parts · 50 堂</sub></td>
  <td align="center"><sub>4 parts · 50 堂</sub></td>
  <td align="center"><sub>3 parts · 50 堂</sub></td>
</tr>
<tr>
  <td valign="top">
    從封包到 kernel<br/>
    從數論到後量子密碼學<br/>
    從 <code>epoll</code> 到 <code>XDP</code>
  </td>
  <td valign="top">
    拆解所有 SOTA 協議到逐行解釋<br/>
    通讀 4+ 個大型開源專案<br/>
    自建 GFW 對抗測試平台
  </td>
  <td valign="top">
    從威脅模型到 spec<br/>
    從形式化驗證到 Go/Rust 實作<br/>
    對抗評測 → 論文初稿
  </td>
</tr>
</table>

<br/>

## 課程地圖

<table>
<thead>
<tr><th align="center">Phase</th><th>Part</th><th>主題</th><th align="center">堂數</th></tr>
</thead>
<tbody>
<tr><td rowspan="6" align="center"><strong>I</strong><br/><sub>Foundations</sub></td>
    <td><code>0</code></td><td>定向、研究方法、文獻地圖</td><td align="center">5</td></tr>
<tr><td><code>1</code></td><td>網路：從電晶體到 BGP</td><td align="center">18</td></tr>
<tr><td><code>2</code></td><td>高效能 I/O 與 kernel 網路</td><td align="center">14</td></tr>
<tr><td><code>3</code></td><td>密碼學：從數論到後量子</td><td align="center">16</td></tr>
<tr><td><code>4</code></td><td>TLS / QUIC 內部完全解剖</td><td align="center">12</td></tr>
<tr><td><code>5</code></td><td>形式化方法</td><td align="center">8</td></tr>
<tr><td rowspan="4" align="center"><strong>II</strong><br/><sub>SOTA Anatomy</sub></td>
    <td><code>6</code></td><td>真 VPN 協議精讀 + 原始碼</td><td align="center">10</td></tr>
<tr><td><code>7</code></td><td>翻牆協議完整演化史</td><td align="center">16</td></tr>
<tr><td><code>8</code></td><td>QUIC 系協議深度</td><td align="center">10</td></tr>
<tr><td><code>9</code></td><td>審查對抗 + 自建測試平台</td><td align="center">14</td></tr>
<tr><td rowspan="3" align="center"><strong>III</strong><br/><sub>Design &amp; Build</sub></td>
    <td><code>10</code></td><td>對抗式流量分析與反制</td><td align="center">12</td></tr>
<tr><td><code>11</code></td><td>設計：威脅模型、spec、形式化驗證</td><td align="center">14</td></tr>
<tr><td><code>12</code></td><td>實作、評測、發表</td><td align="center">24</td></tr>
</tbody>
</table>

完整內容見 [`SYLLABUS.md`](./SYLLABUS.md)。

<br/>

## 怎麼讀這個 repo

| | |
|---|---|
| **想看課程設計** | [`SYLLABUS.md`](./SYLLABUS.md) |
| **想讀課** | [`lessons/`](./lessons/) — 按 Part / 堂編號 |
| **不熟的術語** | [`glossary.md`](./glossary.md) |
| **論文讀書筆記** | [`notes/papers/`](./notes/papers/) |
| **隨堂答疑** | [`qa/`](./qa/) |
| **協議實作（Phase III）** | [`projects/`](./projects/) |

<br/>

## 目錄結構

```text
.
├─ SYLLABUS.md                    完整課程大綱
├─ glossary.md                    術語表（隨課成長）
│
├─ lessons/                       授課主體
│  ├─ part-0-orientation/          ┐
│  ├─ part-1-networking/           │
│  ├─ part-2-high-perf-io/         │  Phase I  地基
│  ├─ part-3-cryptography/         │
│  ├─ part-4-tls-quic/             │
│  ├─ part-5-formal-methods/       ┘
│  ├─ part-6-vpn-internals/        ┐
│  ├─ part-7-proxy-protocols/      │  Phase II SOTA 解剖
│  ├─ part-8-quic-protocols/       │
│  ├─ part-9-gfw-research/         ┘
│  ├─ part-10-traffic-analysis/    ┐
│  ├─ part-11-design/              │  Phase III 設計與實作
│  └─ part-12-implement-evaluate/  ┘
│
├─ notes/papers/                  論文讀書筆記
├─ qa/                            隨堂答疑
├─ assets/                        圖、抓包、配置範例（脫敏）
└─ projects/                      Phase III 程式碼
```

<br/>

## 關於這個 repo

- **這是公開的研究筆記與授課存檔，不是教材製品**。寫法以「對我自己有效」為先。
- **所有範例已脫敏**。沒有真實 VPS IP、域名、UUID、訂閱、私鑰；看到 `vps.example.com` / `198.51.100.42` 之類就是佔位符。
- **歡迎讀，不歡迎照抄**。如果你也在做這個方向，建議拿大綱當骨架，自己跟 Claude 對話填血肉——別人嚼過的飯沒營養。

<br/>

<div align="center">
<sub>Built with curiosity, on a long road. · 2026 —</sub>
</div>
