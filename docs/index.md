# Security Research Portfolio

**CTF writeups with cleaner tradecraft, clearer reasoning, and better presentation.**

A curated archive of challenge solutions across binary exploitation, reverse engineering, web, forensics, cryptography, and OSINT. The goal is not just to dump solves, but to document methodology, constraints, and the reasoning that actually mattered.

[Browse latest event](./unbreakable2026/index.md) | [View ROCSC 2026](./rocsc2026/index.md)

## Overview

- **Platforms:** 7+ (Hack The Box, CyberEDU, pwnable.kr, ROCSC, Unbreakable, and more)
- **Focus Areas:** 6 (Pwn, reversing, web, crypto, forensics, and OSINT)
- **Writeup Style:** Practical (Exploit path, tooling, pitfalls, and verification details over filler)

## Vulnerability Research

In addition to CTF writeups, this site now includes a dedicated vulnerability research track for real-world bug analysis, root-cause writeups, patch diffing, exploitability assessment, and case-study style reporting.

[Open the vulnerability research section](./vulnerability-research/index.md)

## Featured Writeups

- **[Substrate](./unbreakable2026/substrate/writeup.md) (Reverse Engineering):** Windows user-mode and kernel-mode reversing, string recovery via Unicorn emulation, and matrix inversion over modulo 256.
- **[oshi](./rocsc2026/oshi/writeup.md) (Pwn):** Out-of-bounds read to FSOP, with a more advanced exploitation chain than a standard overflow writeup.
- **[open-tellmewhy](./rocsc2026/open-tellmewhy/writeup.md) (Web):** CVE research, browser behavior, and XSS path analysis with a cleaner chain of evidence.

## Browse By Platform

- **[CyberEDU](./cyberedu/index.md)** — Broad category coverage with a strong pwn core and useful foundational exercises.
- **[Hack The Box](./HackTheBox/index.md)** — Selected writeups across web, crypto, reversing, blockchain, and binary exploitation.
- **[HTB University 2025](./HackTheBox-University2025/index.md)** — University-focused event coverage with practical pwn, reverse engineering, and web tasks.
- **[pwnable.kr](./pwnable.kr/index.md)** — Progressive exploitation challenges from entry-level overflows to more structured ROP tasks.
- **[ROCSC 2025](./rocsc2025/index.md)** — Compact set of challenge writeups across math-heavy tasks, OSINT, and steganography.
- **[ROCSC 2026](./rocsc2026/index.md)** — One of the strongest sections in the repository, with coverage across web, pwn, mobile, and AI-themed challenges.
- **[Unbreakable 2026](./unbreakable2026/index.md)** — Writeups spanning reverse engineering, web, threat hunting, forensics, and heap-focused exploitation.

## What Makes A Good Writeup Here

- **Method First:** Each writeup should explain the attack surface, failed assumptions, and what unlocked the solve, not just the final script.
- **Operator Notes:** Tools, debugger behavior, offsets, and environment details matter. The site should preserve that operational context.
- **Reusable Patterns:** The best entries are useful twice: once for the challenge itself and again when the technique reappears somewhere else.

## Recommended Entry Points

- [Substrate](./unbreakable2026/substrate/writeup.md) for polished reverse engineering and binary analysis.
- [ROCSC 2026](./rocsc2026/index.md) for broad multi-category coverage.
- [pwnable.kr](./pwnable.kr/index.md) for the cleanest progression through classic binary exploitation concepts.
- [Hack The Box](./HackTheBox/index.md) for a platform-oriented challenge mix.
