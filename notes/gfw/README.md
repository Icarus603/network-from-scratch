# `notes/gfw/` — GFW operational intelligence

Living record of **real-world GFW operational events** and **industry-leak intelligence**. Distinct from `notes/papers/` (which is for peer-reviewed primary literature) and `notes/specs/` (which is for RFCs / protocol specifications).

## What belongs here

| Type | Examples |
|---|---|
| **Incident notes** | "2025-08-20 unconditional TCP/443 RST event", "2026-04 commercial node mass-disconnection" |
| **Leak analyses** | "2025-09-11 Geedge/MESA 600 GB doc leak (secondary analyses)" |
| **Field-observed behavior changes** | GFW.report blog posts, Xray/Sing-box issue trackers, community measurement reports |
| **Vendor/product intelligence** | Tiangou / TSG / Cyber Narrator capability summaries from public sources |
| **Threat-model updates** | "What's changed in GFW posture since the last research-grade paper" |

## What does NOT belong here

- Peer-reviewed papers → `notes/papers/`
- RFC / IETF draft / protocol spec → `notes/specs/`
- Code-walk notes / source-RE writeups → keep in the lesson that hosts them (`lessons/part-X/X.Y-...`) or open a dedicated `notes/source-walks/` if it grows

## Filename convention

`YYYY-MM-DD-short-topic.md`

- Date = the **event** date (when the incident happened / when the leak dropped), NOT the analysis publication date.
- Short topic = a few words, kebab-case, distinguishing this incident from others on the same day.

Examples:
- `2025-08-20-port443-rst-incident.md` (incident date 2025-08-20, blog analysis 2025-08-22)
- `2025-09-11-geedge-mesa-leak.md` (leak public 2025-09-11, secondary analyses 2025-09-15 onward)

## Frontmatter shape

```yaml
---
name: 2025-08-20-port443-rst-incident
description: <one-line, surface the most actionable fact>
metadata:
  type: gfw-incident-note     # or gfw-leak-note / gfw-capability-note
  source_kind: blog-post-with-packet-captures   # or industry-leak / community-issue-tracker / academic-blog
  prior_path: <if moved from elsewhere>
---
```

## Citation hygiene

These notes are inherently **secondary** sources for non-academic events — bloggers, journalists, Xray issue threads, leaked-archive analyses. Apply the rules from `CLAUDE.md` paper-acquisition section but adapted:

1. **Always fetch + cite the original report URL** (don't summarize from search-result snippets).
2. **Mark "Status: PDF unavailable" or "secondary source only"** explicitly where applicable.
3. **For leak-derived claims**, flag the analyst chain: "InterSecLab says Geedge product X does Y, citing Jira ticket Z" — do not say "the leak proves X does Y" without that intermediate analyst step.
4. **Distinguish documented capabilities from inferred ones**. The Geedge leak shows the *name* "Tiangou Secure Gateway"; what Tiangou *does specifically* still needs source-RE analysis we don't have.

## Update cadence

- After every major GFW event (incident, leak, paper that drops post-cutoff) → write a note here.
- Quarterly digest in `qa/YYYY-MM-DD-gfw-quarterly-threat-intel.md` consolidates and ranks active threats — link each item back to a note here.
- Stale notes (event from > 12 months ago whose mechanism has been superseded) get a top-of-file `Status: SUPERSEDED — see 2026-XX note` rather than deletion. Historical record matters for understanding how the adversary evolved.
