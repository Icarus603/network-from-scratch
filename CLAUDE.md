# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This repo is a personal learning workspace for networking technologies, with a focus on **proxies and VPNs**. The goal is to build conceptual understanding through reading, notes, and hands-on implementations — not to ship a product. Expect topics such as:

- Proxy protocols (HTTP/HTTPS CONNECT, SOCKS4/5, transparent proxies)
- VPN protocols and tunnelling (WireGuard, OpenVPN, IPsec, L2TP)
- Modern censorship-resistance / obfuscation tooling (Shadowsocks, V2Ray/Xray, Trojan, Hysteria, sing-box)
- TLS, SNI, ECH, mTLS, certificate handling
- Userspace TUN/TAP, packet routing, NAT, iptables/nftables, pf (macOS)
- Network namespaces, virtual interfaces, traffic shaping

## Current state

The repository is empty — no source files, no build system, no commits yet. There is therefore **no canonical build/test/lint command** to document. When the user adds code or scaffolding, update this file with the actual toolchain commands at that point (do not invent them in advance).

## Working style for this repo

- **Learning over shipping.** When the user asks for an implementation, prefer minimal, readable, well-commented examples that illustrate the concept over production-grade code. Explain the *why* (protocol semantics, kernel/network behaviour) alongside the *how*.
- **Default explanation language is 繁體中文** (per global user preferences); code comments may be in English unless the user writes them in 中文.
- **Cite specs and RFCs when relevant** (e.g. RFC 1928 for SOCKS5, RFC 8446 for TLS 1.3, the WireGuard whitepaper). Accuracy on protocol details matters more than brevity here.
- **macOS-aware.** The user is on macOS — prefer `pf`/`pfctl`, `utun` interfaces, BSD-flavoured tooling. Mention Linux equivalents (`iptables`/`nftables`, `tun`/`tap` via `/dev/net/tun`, network namespaces) when they differ meaningfully, since most proxy/VPN tooling documentation assumes Linux.
- **Language defaults** (from global config) apply when the user starts coding:
  - Go → `go.mod`, `gofmt`, `golangci-lint v2`, `staticcheck`
  - Rust → Cargo, `cargo fmt --all`, `cargo clippy -- -D warnings`, `cargo nextest`
  - Python → `uv` + `pyproject.toml`, `ruff`, `pytest`
  - Node → `bun` (`bun add`, `bun run`)
  - C/C++ → CMake; Homebrew `llvm` for modern clang on macOS
- **Check latest versions before pinning** any framework/library (especially fast-moving tooling like sing-box, Xray-core, hysteria, wireguard-go).

## When the user asks to set things up

If the user says "let's start a Go project for a SOCKS5 proxy" (or similar), do the full scaffold in one go: `go mod init`, directory layout, a runnable `main.go`, README stub, `.gitignore`. Don't ask permission for each step. After scaffolding, update this CLAUDE.md with the concrete build/run/test commands for that subproject.

If multiple independent learning subprojects accumulate (e.g. `socks5-go/`, `wireguard-rs/`, `notes/`), document each one's commands under its own subsection rather than mixing them.
