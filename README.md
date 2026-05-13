# network-from-scratch

> 從零開始學網路、代理、VPN，目標是能自己設計一個翻牆協議。
> 我（Icarus）和 Claude 一起的長期授課存檔。

**起點**：能用一鍵腳本在 VPS 上搭機場 + Clash Verge Rev 客戶端，但網路理論完全零基礎。
**終點**：能自己設計一個代理協議，並寫出可跑的 MVP。

## 關於這個 repo

- **這是公開的學習筆記，不是教材製品**。寫法以「對我自己有效」為先，不保證對其他讀者最佳。
- **所有範例已脫敏**。沒有真實 VPS IP、域名、UUID、訂閱、私鑰。看到 `vps.example.com` / `198.51.100.42` 之類就是佔位符。
- **歡迎讀，不歡迎照抄當教程**。如果你也在學網路，建議拿這份大綱當骨架，自己跟 Claude 對話填血肉——別人嚼過的飯沒營養。

## 怎麼讀這個 repo

1. 先看 [`SYLLABUS.md`](./SYLLABUS.md) — 完整課程大綱（10 個 Part，~60 堂）。
2. 按順序讀 [`lessons/`](./lessons/) 下每一堂課。
3. 不熟的術語去 [`glossary.md`](./glossary.md) 查。
4. 不在大綱裡的隨堂提問記在 [`qa/`](./qa/)。
5. Part 10 開始的動手實作放在 [`projects/`](./projects/)。

## 目錄結構

```
.
├── README.md           ← 你正在看的這份
├── CLAUDE.md           ← Claude 的工作指引
├── SYLLABUS.md         ← ⭐ 完整課程大綱
├── glossary.md         ← 術語表（隨課成長）
├── lessons/            ← 授課主體，按 Part / 堂編號
│   ├── part-0-orientation/
│   ├── part-1-foundations/
│   ├── part-2-transport-application/
│   ├── part-3-crypto-tls/
│   ├── part-4-os-network-stack/
│   ├── part-5-vpn-protocols/
│   ├── part-6-proxy-protocols/
│   ├── part-7-airport-anatomy/
│   ├── part-8-client-and-rules/
│   ├── part-9-anti-censorship/
│   └── part-10-build-your-own/
├── qa/                 ← 隨堂答疑（不在主課程內的問題）
├── assets/             ← 圖、抓包樣本、配置範例
└── projects/           ← Part 10 開始的動手實作
```
