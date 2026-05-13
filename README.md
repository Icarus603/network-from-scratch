<div align="center">

# 隱渡

### 抗審查 × 高效能代理協議的研究級課程

<sub>network-from-scratch · 由 [Icarus](https://github.com/Icarus603) 與 Claude 共同建立的長期授課與研究存檔</sub>

<br/>

[![Lessons](https://img.shields.io/badge/lessons-1%20%2F%20150-blue?style=flat-square)](./SYLLABUS.md)
[![Phase](https://img.shields.io/badge/phase-I%20Foundations-orange?style=flat-square)](./SYLLABUS.md)
[![Last Commit](https://img.shields.io/github/last-commit/Icarus603/network-from-scratch?style=flat-square)](https://github.com/Icarus603/network-from-scratch/commits/main)
[![Language](https://img.shields.io/badge/lang-繁體中文-red?style=flat-square)](#)

</div>

---

<div align="center">

> *起點 ──*
> 能搭一座機場，
> 卻不識封包為何物。
>
> *終點 ──*
> 親手鑿一條新路，
> 隱於牆，疾如光。

</div>

<br/>

## 三段路

<table>
<tr>
  <th width="33%" align="center">其　一</th>
  <th width="33%" align="center">其　二</th>
  <th width="33%" align="center">其　三</th>
</tr>
<tr>
  <td align="center"><strong>築基</strong></td>
  <td align="center"><strong>解牆</strong></td>
  <td align="center"><strong>立路</strong></td>
</tr>
<tr>
  <td align="center"><sub>6 章 · 50 堂</sub></td>
  <td align="center"><sub>4 章 · 50 堂</sub></td>
  <td align="center"><sub>3 章 · 50 堂</sub></td>
</tr>
<tr>
  <td valign="top">
    自封包至 kernel，<br/>
    自數論至後量子，<br/>
    自 <code>epoll</code> 至 <code>XDP</code>。
  </td>
  <td valign="top">
    拆 SOTA 至逐行可釋，<br/>
    讀四部開源原典，<br/>
    自建 GFW 對抗之地。
  </td>
  <td valign="top">
    自威脅模型至規格，<br/>
    自形式化證明至實作，<br/>
    自評測至論文。
  </td>
</tr>
</table>

<br/>

## 十二章

<table>
<thead>
<tr><th align="center">　</th><th>章</th><th>題</th><th align="center">堂</th></tr>
</thead>
<tbody>
<tr><td rowspan="6" align="center"><strong>築<br/>基</strong></td>
    <td><code>0</code></td><td>定向、方法、文獻地圖</td><td align="center">5</td></tr>
<tr><td><code>1</code></td><td>網路：從電晶體到 BGP</td><td align="center">18</td></tr>
<tr><td><code>2</code></td><td>高效能 I/O 與 kernel 網路</td><td align="center">14</td></tr>
<tr><td><code>3</code></td><td>密碼學：從數論到後量子</td><td align="center">16</td></tr>
<tr><td><code>4</code></td><td>TLS / QUIC 內部完全解剖</td><td align="center">12</td></tr>
<tr><td><code>5</code></td><td>形式化方法</td><td align="center">8</td></tr>
<tr><td rowspan="4" align="center"><strong>解<br/>牆</strong></td>
    <td><code>6</code></td><td>真 VPN 協議精讀 + 原始碼</td><td align="center">10</td></tr>
<tr><td><code>7</code></td><td>翻牆協議完整演化史</td><td align="center">16</td></tr>
<tr><td><code>8</code></td><td>QUIC 系協議深度</td><td align="center">10</td></tr>
<tr><td><code>9</code></td><td>審查對抗 + 自建測試平台</td><td align="center">14</td></tr>
<tr><td rowspan="3" align="center"><strong>立<br/>路</strong></td>
    <td><code>10</code></td><td>對抗式流量分析與反制</td><td align="center">12</td></tr>
<tr><td><code>11</code></td><td>設計：威脅模型、規格、形式化驗證</td><td align="center">14</td></tr>
<tr><td><code>12</code></td><td>實作、評測、發表</td><td align="center">24</td></tr>
</tbody>
</table>

完整大綱見 [`SYLLABUS.md`](./SYLLABUS.md)。

<br/>

## 行路指南

| | |
|---|---|
| **大綱** | [`SYLLABUS.md`](./SYLLABUS.md) |
| **正課** | [`lessons/`](./lessons/) |
| **辭典** | [`glossary.md`](./glossary.md) |
| **論文札記** | [`notes/papers/`](./notes/papers/) |
| **隨堂答疑** | [`qa/`](./qa/) |
| **協議實作** | [`projects/`](./projects/) |

<br/>

## 屋宇

```text
.
├─ SYLLABUS.md                    大綱
├─ glossary.md                    辭典
│
├─ lessons/                       正課
│  ├─ part-0-orientation/          ┐
│  ├─ part-1-networking/           │
│  ├─ part-2-high-perf-io/         │  築基
│  ├─ part-3-cryptography/         │
│  ├─ part-4-tls-quic/             │
│  ├─ part-5-formal-methods/       ┘
│  ├─ part-6-vpn-internals/        ┐
│  ├─ part-7-proxy-protocols/      │  解牆
│  ├─ part-8-quic-protocols/       │
│  ├─ part-9-gfw-research/         ┘
│  ├─ part-10-traffic-analysis/    ┐
│  ├─ part-11-design/              │  立路
│  └─ part-12-implement-evaluate/  ┘
│
├─ notes/papers/                  論文札記
├─ qa/                            隨堂答疑
├─ assets/                        圖、抓包、脫敏配置
└─ projects/                      協議實作
```

<br/>

## 幾句叮嚀

<div align="center">

### 築基非朝夕　解牆豈一書
### 真名皆隱去　密匙不留餘
### 獨坐推沙策　親行鑿石渠
### 路長無捷處　唯與夜燈居

</div>

<br/>

<div align="center">
<sub>長路初啟　·　2026 —</sub>
</div>
