# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is a personal **research-grade course on censorship-resistant + high-performance proxy protocols**, authored by Claude for the user (Icarus). It is also the staging ground for the **actual research project** the course leads to: designing and implementing a new proxy protocol that simultaneously matches **VLESS+REALITY-grade anti-censorship** and **Hysteria2 / TUIC-v5-grade speed** — i.e. a new SOTA.

The user is a complete networking beginner on the theory side, but already deploys a VPS proxy stack with `ccb` and Clash Verge Rev. Commitment window: 1.5–3 years, 10–20 hours/week. Treat the user as a PhD-track student and yourself as advisor + research collaborator.

The full structure is documented in [`README.md`](./README.md) and the syllabus lives in [`SYLLABUS.md`](./SYLLABUS.md).

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
.
├── README.md                      ← entry point
├── CLAUDE.md                      ← you are here
├── SYLLABUS.md                    ← v2 research-grade syllabus (3 phases / 12 parts / ~150 lessons)
├── glossary.md                    ← term index, grows lesson-by-lesson
├── lessons/                       ← course body
│   ├── part-0-orientation/         Phase I  — Foundations
│   ├── part-1-networking/
│   ├── part-2-high-perf-io/
│   ├── part-3-cryptography/
│   ├── part-4-tls-quic/
│   ├── part-5-formal-methods/
│   ├── part-6-vpn-internals/       Phase II — SOTA Anatomy
│   ├── part-7-proxy-protocols/
│   ├── part-8-quic-protocols/
│   ├── part-9-gfw-research/
│   ├── part-10-traffic-analysis/   Phase III — Design & Build
│   ├── part-11-design/
│   └── part-12-implement-evaluate/
├── notes/papers/                  ← per-paper reading notes
├── qa/                            ← off-syllabus Q&A
├── assets/                        ← diagrams, redacted configs, captures
└── projects/                      ← Phase III code (protocol impl, test harness)
```

## Teaching workflow

When the user asks to "start lesson X.Y" (e.g. "開始第 0.1 堂"), do all of the following without asking permission:

1. Create `lessons/part-N-name/X.Y-slug.md` using the **lesson template** below.
2. Write the lesson content. Length target depends on Part:
   - Phase I (Parts 0–5): 20–40 minutes of reading per lesson, dense but linear.
   - Phase II (Parts 6–9): 30–60 minutes — includes paper precis and source-code walks.
   - Phase III (Parts 10–12): variable, may span multiple sessions per "lesson".
3. Use 繁體中文 prose. Code identifiers, RFC names, paper titles, and technical terms stay in English.
4. Add any new terms to `glossary.md` (don't redefine terms that already exist there — link to them).
5. If the lesson references a paper, create or update `notes/papers/<short-id>.md` with a precis (problem / contribution / method / limitation / how it informs our protocol design).
6. Tick the lesson off in `SYLLABUS.md` by appending ✅ to the corresponding bullet, e.g. `### 0.1 「VPN」這個詞被誤用了 30 年 ✅`.

### Lesson file template

```markdown
# 課堂 X.Y — 標題

## 學前知道
- 前置課：...
- 預計閱讀時間：...
- 必讀論文：（如有）
- 必讀原始碼：（如有，含具體檔案 + 函數）

## 動機
為什麼要學這個？對「設計新 SOTA 協議」的研究目標有何貢獻？

## 核心概念
（主體內容，配 ASCII / Mermaid 圖、必要時用 code block 展示 RFC 引文或原始碼片段）

## 與我們協議設計的關聯
這一節學到的東西會在 Part 11/12 怎麼用？

## 動手（可選）
實驗、抓包、原始碼追蹤、形式化建模 —— 視 lesson 性質而定。

## 自我檢查
3~5 個研究級問題，答得出來才算過關。

## 延伸閱讀
延伸的論文、blog、原始碼。
```

### Style rules for lessons

- **Be research-grade, not blog-grade.** Cite primary sources (RFCs by number, papers by venue + year + authors). When discussing algorithms, cite the original paper, not a secondary tutorial.
- **No hand-waving.** If something is approximated for pedagogy, say so explicitly and link to where the exact version is taught later.
- **Anchor to the user's existing experience** (Clash settings, ccb panels, real subscription field meanings) when it helps comprehension.
- **macOS-aware but Linux-first for kernel/perf topics.** The user develops on macOS but most kernel/eBPF/XDP topics will require Linux experiments (VPS or VM). Mention both, default to Linux for perf-critical material.
- **Source-code references are concrete.** Quote `path/to/file.go:LINE` style, not "somewhere in xray".
- **Diagrams in ASCII or Mermaid only** unless the user explicitly asks for raster.

## Off-syllabus questions

When the user asks something not covered by the current lesson plan, save the Q&A to `qa/YYYY-MM-DD-short-topic.md` using the template in `qa/README.md`. Cross-link to the relevant Part/lesson in the syllabus, both backward (where this question relates to past learning) and forward (where it will be deepened).

## Paper reading notes

Whenever a lesson cites a paper, ensure `notes/papers/<short-id>.md` exists. Format:

```markdown
# <Paper title>
**Venue / Year**: ...
**Authors**: ...
**Read on**: YYYY-MM-DD (in lesson X.Y)
**One-line**: ...

## Problem
## Contribution
## Method (just enough to reproduce mentally)
## Limitations / what they don't solve
## How it informs our protocol design
## Open questions
```

## Project commands

`projects/` is for Phase III (Parts 11–12). When a sub-project is added, document its build/run/test commands here under a per-project subsection. Default toolchains:

- Go: `go.mod`, `gofmt`, `golangci-lint v2`, `staticcheck`, `go test ./...`
- Rust: Cargo, `cargo fmt --all`, `cargo clippy -- -D warnings`, `cargo nextest`
- Python: `uv` + `pyproject.toml`, `ruff`, `pytest`
- Node: `bun` (`bun add`, `bun run`)

Always check the latest published version of any dependency before pinning.

## Tool usage for research

Two tools matter a lot for this course and should be used proactively:

- **context7 MCP**: for fetching current docs on libraries / RFCs / protocol implementations (quic-go, xray, sing-box, ring, libsodium, etc.). Use whenever discussing concrete APIs.
- **WebFetch / WebSearch**: for papers published after model knowledge cutoff, GFW.report updates, draft RFCs in flight. Use whenever the topic is fast-moving.

If a paper or claim post-dates the model's training cutoff, fetch it before quoting — don't fabricate.

## Memory system

Persistent user/feedback/project/reference memory lives at `/Users/liuzetfung/.claude/projects/-Users-liuzetfung-code-vpn-learn/memory/`. Indexed via `MEMORY.md` there. See the auto-memory section of the global system prompt for the protocol.

Save to memory when: the user reveals research preferences, accepts/rejects a teaching style, decides on a major scoping question (e.g. "we will use Rust not Go" or "we'll target MASQUE-based transport"). Don't save lesson content (it's already in `lessons/`).
