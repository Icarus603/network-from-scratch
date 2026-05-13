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
5. **Run the closing checklist** below — *every* lesson, no exception.
6. Tick the lesson off in `SYLLABUS.md` by appending ✅ to the corresponding bullet, e.g. `### 0.1 「VPN」這個詞被誤用了 30 年 ✅`.

### Closing checklist (mandatory, run after every lesson)

This is the single mechanism that enforces all the discipline rules elsewhere in this file. **Do not skip.** If you finish writing a lesson and have not done the following audit, the lesson is incomplete.

Walk through the lesson you just wrote and answer each question explicitly (in your own thinking, not in the lesson file). For each "yes", take the action.

```
[ ] 1. Did I cite any paper, RFC, or whitepaper in this lesson?
       → For each: classify A/B/C per "Paper acquisition" rules.
       → For each B/C: fetch PDF, write precis, check it in.
       → For each A: confirm I'm certain about title/venue/year; fetch if not.

[ ] 2. Did I cite source code (`path/to/file.go:LINE`)?
       → Verify the file exists and the line range still matches in the
         project's HEAD or specific tag I cited.

[ ] 3. Did I introduce any new term?
       → Add to `glossary.md` with type, layer, first-appearance link.

[ ] 4. Did I make any forward reference (「Part X.Y 詳講」)?
       → Verify Part X.Y exists in SYLLABUS.md and the topic actually
         belongs there. If misplaced, fix the reference or the syllabus.

[ ] 5. Does the lesson have a 研究級補遺 section?
       → If no: write it now (≥3 of the 7 sub-sections).
       → 學界詞彙 + 我們協議的座標 are nearly always required.

[ ] 6. Are diagrams in Mermaid (not ASCII box-drawing)?
       → If any ASCII art with CJK, rewrite as Mermaid or markdown table.

[ ] 7. Backfill audit: am I writing this lesson AFTER a workflow rule
       was added? Did earlier lessons (0.1, 0.2, ...) ship without
       compliance to the now-current rules?
       → If yes: list the gaps to the user, propose a backfill plan.
       → DO NOT silently ignore historical lessons because the rule
         is "newer than them" — rules apply retroactively unless the
         user says otherwise.

[ ] 8. .gitkeep cleanup: did I add real content to any directory that
       previously held only a .gitkeep placeholder?
       → Delete the .gitkeep — its only job was to keep the empty
         directory tracked by git, and now real files do that job.
       → Quick check: `find lessons notes assets projects qa -name .gitkeep`
         and remove any whose parent directory has other files.

[ ] 9. Tell the user what was produced this round, including any
       fetched papers / written precis / glossary additions, so the
       user can verify nothing was missed.
```

The point of writing this as a checklist (not prose) is that it's **mechanically auditable**. Future-you (or another Claude session) should be able to read the lesson and run the checklist independently.

### Lesson file template

Every lesson MUST follow this structure. The 「研究級補遺」 section is non-negotiable — see "Research-grade bar" below for why.

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
（主體內容，Mermaid 圖、markdown 表格、必要時用 code block 展示 RFC 引文或原始碼片段）

## 與我們協議設計的關聯
這一節學到的東西會在 Part 11/12 怎麼用？

## 動手（可選）
實驗、抓包、原始碼追蹤、形式化建模 —— 視 lesson 性質而定。

## 自我檢查
3~5 個研究級問題，答得出來才算過關。

## 延伸閱讀
延伸的論文、blog、原始碼。

---

## 研究級補遺

> 主體保持友善基調，這節把「友善版」升級成「研究級」入口。新手可跳過，研究員必讀。

（按 lesson 性質從以下面向選 3~6 個寫——不必全選，但「學界詞彙」與「我們協議的座標」幾乎每堂都該有）

### 1. 學界詞彙
本堂概念在學術文獻裡的標準術語、慣用縮寫。讓使用者之後 google / 翻論文時用對詞。

### 2. 對手分類學 / 威脅模型精化
（如本堂涉及安全或對抗）口語描述升級成 on-path/off-path × passive/active × adaptive 級別的精確分類。引 Dolev-Yao 等標準模型。

### 3. 形式化定義
口語版概念對應的 formal definition（密碼學定義、計算複雜度、安全屬性 game-based definition 等）。

### 4. 領域的關鍵論文 / 規格 / 原始碼
3~10 個必追的 primary source。每個用一行說「為什麼追」+ 「之後在哪一堂精讀」。

### 5. 我們協議的座標 / 設計取捨
本堂內容在 G6 設計空間中的位置：哪些選擇仍 open、哪些已被本堂內容收窄、Part 11 設計時哪一節會回頭引用。

### 6. 必追資源 / 社群入口
GFW.report、IETF working group、IACR ePrint subscription、相關 GitHub issue tracker、領域內研究者的個人 blog 等。新手不必立刻讀，建立 awareness 即可。

### 7. 開放問題（research-level open problems）
本堂內容**還沒被解決**的問題，將來如果我們想推到頂會（USENIX Security / NDSS / CCS）的方向。

```

### Research-grade bar

This course is not a tutorial series. The user's commitment is **PhD-track**: 1.5–3 years, original SOTA contribution as the deliverable. Every lesson must therefore meet a research-grade bar — not just a "well-written blog post" bar. Concretely:

- **Every lesson ships with a 研究級補遺 section** at the end. No exceptions, even for orientation lessons. Do not ask the user whether to add it. Pick at minimum 3 of the 7 sub-sections from the lesson template (學界詞彙 + 我們協議的座標 are nearly always present).
- **Every concept name has a citation.** Even in body text. If you introduce 「BBR」, cite *Cardwell et al., CACM 2017*. If you introduce 「Dolev-Yao」, cite *Dolev & Yao, IEEE TIT 1983*. If a citation can't be produced from your own training, fetch it via `WebFetch` / context7 before writing — do not bluff.
- **Every claim about an attack / defense / measurement has a primary source.** "GFW does X" must be backed by a GFW.report / IMC / USENIX Security paper, never a blog or hearsay.
- **Forward references are concrete.** Not 「Part 11 詳講」 but 「Part 11.10 ProVerif 驗證」 — pinpoint the lesson number that will deepen this point.
- **Source-code citations are line-precise.** Not 「somewhere in Xray-core」 but `transport/internet/reality/reality.go:123-178`.
- **Failure framing is built in.** Research is mostly failure. Lessons should set expectations that hypotheses get killed, designs get rewritten — never present knowledge as if the field's path was inevitable.
- **No advisor-student deference.** Push back on the user's misconceptions; flag where their existing Clash mental model is incomplete or misleading; tell them when a question is malformed.

If a lesson cannot be written to this bar (e.g. the topic is genuinely tutorial-only), say so explicitly in the 學前知道 section and explain why — don't silently downgrade.

### Style rules for lessons

- **Be research-grade, not blog-grade.** Cite primary sources (RFCs by number, papers by venue + year + authors). When discussing algorithms, cite the original paper, not a secondary tutorial.
- **No hand-waving.** If something is approximated for pedagogy, say so explicitly and link to where the exact version is taught later.
- **Anchor to the user's existing experience** (Clash settings, ccb panels, real subscription field meanings) when it helps comprehension.
- **macOS-aware but Linux-first for kernel/perf topics.** The user develops on macOS but most kernel/eBPF/XDP topics will require Linux experiments (VPS or VM). Mention both, default to Linux for perf-critical material.
- **Source-code references are concrete.** Quote `path/to/file.go:LINE` style, not "somewhere in xray".

### Diagrams: Mermaid only, never ASCII art

**Hard rule**: every flowchart, dependency graph, family tree, decision tree, sequence diagram, state machine, packet layout, or any other figure that has structure beyond a flat list — use **Mermaid**, not ASCII box-drawing characters.

**Why this rule exists**: ASCII art assumes monospace alignment, which breaks for CJK characters. East-Asian glyphs render at non-deterministic widths (~1.7x to ~2.0x of an ASCII char depending on font/browser), so any 「box」 or 「arrow」 made of `┌─┐ │ ▼` shifts and tears apart the moment Chinese is inside. We learned this the hard way in lessons 0.1 and 0.2 v1 — both had to be rewritten.

**Practical guidance**:

- **Use Mermaid for**: family trees, dependency DAGs, decision trees, sequence diagrams (`sequenceDiagram`), state machines (`stateDiagram-v2`), packet/frame layouts (use `classDiagram` or `flowchart` with grouped nodes), Phase/Part overviews.
- **Use Markdown tables for**: comparison matrices, parameter lists, threat-model rows.
- **Use ordered/unordered lists for**: any flat enumeration.
- **Plain triple-backtick code fences are fine for**: actual code, RFC excerpts, terminal output. These should never be used to draw diagrams.

**Mermaid conventions for this repo**:

- Default to `flowchart TD` (top-down) for hierarchies, `flowchart LR` (left-right) for pipelines/timelines.
- Highlight 「我們的協議 / 研究產出」nodes with a `classDef ours fill:#fde,stroke:#c39` so they stand out across all lessons.
- Use `subgraph` for Phase boundaries (`Phase I` / `Phase II` / `Phase III`).
- Use dotted edges (`-. label .->`) for 「回路 / forward reference」relationships, solid edges for hard dependency.
- Keep node labels short. Long Chinese strings should be wrapped with `<br/>` or split into multiple lines via `["第一行<br/>第二行"]`.
- For packet/byte layouts where Mermaid is awkward, prefer a Markdown table with one byte/field per row instead of attempting ASCII art.

**Reader environment note**: The user's VS Code now has Mermaid preview enabled (Markdown Preview Mermaid Support extension). GitHub renders Mermaid natively. Both render fine — assume Mermaid will be visible.

## Off-syllabus questions

When the user asks something not covered by the current lesson plan, save the Q&A to `qa/YYYY-MM-DD-short-topic.md` using the template in `qa/README.md`. Cross-link to the relevant Part/lesson in the syllabus, both backward (where this question relates to past learning) and forward (where it will be deepened).

## Paper acquisition: fetch proactively, never wait to be asked

Treat paper acquisition as part of writing a lesson, not a separate request. **Do not** finish a lesson, mention "Foo et al. 2024", and stop there waiting for the user to download the PDF. Decide which of the three categories below the paper falls into, then act.

### Three paper categories

| Type | Example | Action |
|---|---|---|
| **A. Foundational, in training data** | TLS 1.3 (RFC 8446), Curve25519 (Bernstein 2006), Noise framework | Cite confidently. Fetch only if a lesson does a *deep* read (Keshav second/third pass). |
| **B. Field-defining, post-cutoff or semi-rare** | GFW.report papers, FlowPrint NDSS 2020, FEP USENIX Security 2023 | **Fetch on first cite.** Verify venue/year/authors against the actual PDF metadata. Write a precis in `notes/papers/`. |
| **C. Cutoff-after / draft / preprint** | IETF drafts in flight, arXiv-only preprints, IACR ePrint, GFW.report posts after model cutoff | **Always fetch.** Never quote details from memory — risk of hallucination is too high. |

### Triggers that obligate a fetch (do not wait to be asked)

1. A lesson uses the paper as **primary evidence** for a claim — fetch + precis.
2. The lesson's 研究級補遺 lists the paper as 必追 — fetch + verify metadata at minimum.
3. **Author / title / venue is not 100% certain** from your training — must fetch before writing the citation.
4. The paper is a **direct design influence** on our protocol — fetch + Keshav third-pass precis.
5. The user asks about a specific paper's details — fetch immediately, never answer from memory alone for paper-specific facts.

### Default: fetch ALL cited papers, do not ask

When a lesson cites multiple papers and any of them satisfy the triggers above, **fetch all of them in one go**. Do **not** present the user with a prioritised list and ask "should I fetch these N papers?" — that is exactly the "wait to be asked" anti-pattern this section forbids.

The acceptable defaults:

- **Default action**: fetch every cited paper that's not category A (foundational, in training data, certain). Write precis for each.
- **Only ask the user when**:
  - A fetch genuinely fails after retries with multiple mirrors (paywall, dead link, geographic restriction). Tell the user *which* paper failed and what mirrors you tried — let them help locate it.
  - The list is enormous (>20 papers in one lesson, e.g. literature-map lessons like 0.4) — then propose a batching schedule, not a "should I do this?" question.
- **Never ask** "do you want me to fetch all 6?" / "should I also grab the optional ones?" — the answer is always yes for any cited paper above category A. The user has explicitly said they don't want to be the gatekeeper for fetch decisions.

### Fetch tooling, in priority order

1. **`WebFetch`** for direct PDF / HTML mirrors (USENIX open access, ACM Authorizer, arXiv, IACR ePrint, GFW.report).
2. **`WebSearch`** to locate the right URL when not directly known: `"{exact title}" filetype:pdf` is the most reliable query shape.
3. **context7 MCP** for RFCs and well-documented library docs.
4. **Google Scholar / DBLP** for citation metadata when the PDF host is uncertain.

### Where to put the file

- **PDF (local-only, not committed)**: `assets/papers/{venue}-{year}-{shortid}.pdf` — covered by `.gitignore`. Reason: copyright. We can re-download anytime; the precis is what we keep.
- **Precis (committed)**: `notes/papers/{shortid}.md` — see template below.
- **Cross-reference**: every lesson that cites the paper links to `notes/papers/{shortid}.md`; every precis links back to the lesson(s) that reference it.

### Honesty rule

If a fetch fails (paywall, dead link, can't find PDF) — **say so explicitly in the precis** (`Status: PDF unavailable, citing only from abstract / blog summary`). Never silently downgrade a missing-PDF cite into a confident from-memory cite.

### Precis template (`notes/papers/<short-id>.md`)

```markdown
# <Paper title>
**Venue / Year**: ...
**Authors**: ...
**Read on**: YYYY-MM-DD (in lesson X.Y)
**Status**: full PDF / abstract-only / unavailable
**One-line**: ...

## Problem
## Contribution
## Method (just enough to reproduce mentally)
## Results
## Limitations / what they don't solve
## How it informs our protocol design
## Open questions
## References worth following
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
