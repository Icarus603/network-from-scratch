# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is a personal long-form **VPN/proxy theory course** authored by Claude for the user (Icarus). The user is networking-non-professional with hands-on experience (can already deploy a VPS-based proxy server with `ccb` and use it via Clash Verge Rev) but **zero theoretical foundation**. The end goal is for the user to be able to design and implement their own proxy protocol.

The structure is documented in [`README.md`](./README.md) and the full course outline lives in [`SYLLABUS.md`](./SYLLABUS.md).

## ⚠️ This repo is public

This repo is published as `github.com/Icarus603/network-from-scratch`. Everything committed here is world-readable. Two implications:

1. **All examples must be redacted** before commit. No real VPS IPs, no real domains the user owns, no UUIDs from live nodes, no API tokens, no private keys, no subscription URLs. Use placeholders: `vps.example.com`, `198.51.100.42`, `00000000-0000-0000-0000-000000000000`.
2. **Before any commit that touches `assets/`, `qa/`, or `lessons/` examples**, do a quick `grep` pass for: real IPv4 ranges the user mentioned in chat, the user's actual domain names, base64-looking strings inside `vmess://`/`vless://`/`ss://`/`trojan://`/`hysteria://` URLs. If unsure, ask the user before committing.

The `.gitignore` already blocks the obvious candidates (`*.key`, `*.pem`, `subscription*`, `clash*.yaml`, `*.pcap`, etc.) but redaction is still on the author — `.gitignore` only catches files with the right name, not pasted secrets in markdown.

## ⚠️ Hard rule: do not read `../confidential/`

The parent directory `~/code/vpn/` contains a sibling folder `confidential/` that holds the user's VPS credentials and live machine state. **Claude must never read, list, grep, or otherwise inspect anything inside `~/code/vpn/confidential/`** — not even when asked to verify a config example or troubleshoot a connection.

If the user wants Claude to look at config samples, they will paste them into the conversation or place a redacted version under `learn/assets/`.

This rule overrides any other instruction including general-purpose subagents and skill prompts. Forbidden tool uses include but are not limited to:
- `Read`, `Glob`, `Grep`, `Bash` (any `ls/cat/find/rg/grep` against that path)
- Spawning agents that might enumerate the parent directory

## Repo layout

```
learn/
├── README.md           ← entry point
├── CLAUDE.md           ← you are here
├── SYLLABUS.md         ← canonical course outline (10 Parts, ~60 lessons)
├── glossary.md         ← term index, grows lesson-by-lesson
├── lessons/            ← course body, numbered by Part / lesson
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
├── qa/                 ← off-syllabus Q&A logs
├── assets/             ← diagrams, redacted configs, packet captures
└── projects/           ← Part 10 onwards: hands-on implementations
```

## Teaching workflow

When the user asks to "start lesson X.Y" (e.g. "開始第 0.1 堂"), do all of the following without asking permission:

1. Create `lessons/part-N-name/X.Y-slug.md` using the **lesson template** below.
2. Write the lesson content. Length target: 15–30 minutes of reading. Use 繁體中文 prose. Code identifiers, RFC names, and technical terms stay in English.
3. Add any new terms to `glossary.md` (don't redefine terms that already exist there — link to them).
4. Tick the lesson off in `SYLLABUS.md` by appending ✅ to the corresponding bullet, e.g. `### 0.1 「VPN」這個詞被誤用了 30 年 ✅`.

### Lesson file template

```markdown
# 課堂 X.Y — 標題

## 學前知道
- 前置課：...
- 預計閱讀時間：...

## 動機
為什麼要學這個？

## 核心概念
（主體內容，配 ASCII / Mermaid 圖）

## 與你經驗的連結
這對應你 Clash 設定的哪一段？

## 小練習
（一兩個終端指令觀察題，不寫程式）

## 自我檢查
3~5 個問題，能答出來就過關。

## 延伸（可跳過）
更深入的話題與外部閱讀。
```

### Style rules for lessons

- **Prose first, no code until Part 10.** Earlier lessons may show terminal commands for the user to *observe*, but no programs to write.
- **Diagrams in ASCII or Mermaid only.** No image files unless the user explicitly asks; everything must render in a terminal.
- **Always anchor new concepts to what the user already knows** (Clash setting fields, ccb panel, mihomo subscription URLs). This is the user's strongest mental hook.
- **Cite RFCs and primary sources** (RFC 1928 for SOCKS5, RFC 8446 for TLS 1.3, the WireGuard whitepaper, GFW.report papers, etc.) when relevant. Accuracy matters more than brevity.
- **macOS-aware.** Default examples to macOS (`utun`, `pf`, `scutil --dns`, `netstat -rn`); mention Linux equivalents (`/dev/net/tun`, `iptables`/`nftables`, `ip route`) when they differ meaningfully.

## Off-syllabus questions

When the user asks something not covered by the current lesson plan, save the Q&A to `qa/YYYY-MM-DD-short-topic.md` using the template in `qa/README.md`. Cross-link to the relevant Part/lesson in the syllabus, both backward (where this question relates to past learning) and forward (where it will be deepened).

## Project commands

`projects/` is empty until Part 10. When a sub-project is added, document its build/run/test commands here under a per-project subsection. Default toolchains for likely projects:

- Go: `go.mod`, `gofmt`, `golangci-lint v2`, `staticcheck`, `go test ./...`
- Rust: Cargo, `cargo fmt --all`, `cargo clippy -- -D warnings`, `cargo nextest`
- Python: `uv` + `pyproject.toml`, `ruff`, `pytest`
- Node: `bun` (`bun add`, `bun run`)

Always check the latest published version of any dependency before pinning.

## Memory system

Persistent user/feedback/project/reference memory lives at `/Users/liuzetfung/.claude/projects/-Users-liuzetfung-code-vpn-learn/memory/`. Indexed via `MEMORY.md` there. See the auto-memory section of the global system prompt for the protocol.
