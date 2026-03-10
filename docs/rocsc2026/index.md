# ROCSC 2026

Broadest coverage in the repository, spanning web, pwn, OSINT, mobile, steganography, AI, and network analysis. This event is the best entry point if you want range rather than depth in a single category.

**16 Writeups** · Web · Pwn · OSINT · Mobile · AI

---

## Cryptography

Focused cryptanalytic work with a stronger math component than the rest of the event.

| Challenge | Description |
|-----------|-------------|
| [fifteen-minutes](./fifteen-minutes/writeup/) | Lattice-based recovery with a methodical reduction workflow. |

## Web

Frontend quirks, XSS, and research-heavy application attacks.

| Challenge | Description |
|-----------|-------------|
| [Y](./Y/writeup/) | CSS escape plus XSS in a compact but non-trivial browser-side chain. |
| [open-tellmewhy](./open-tellmewhy/writeup/) | CVE research and XSS backed by versioning and product analysis. |

## OSINT

Footprinting, reverse image workflows, and open-source correlation across multiple public sources.

| Challenge | Description |
|-----------|-------------|
| [museum](./museum/writeup/) | Reverse image search and artifact correlation. |
| [wonderful-strangers](./wonderful-strangers/writeup/) | Identity discovery using Sherlock-style account pivoting. |
| [art-gallery-heist](./art-gallery-heist/writeup/) | Footprinting and social-media driven attribution. |

## Pwn

Classic control-flow abuse next to stronger primitives such as OOB disclosure and file-structure oriented programming.

| Challenge | Description |
|-----------|-------------|
| [directory](./directory/writeup/) | Buffer overflow with a partial return-address overwrite path. |
| [ropy](./ropy/writeup/) | Two-stage ROP chain construction with a more structured pivot. |
| [oshi](./oshi/writeup/) | Out-of-bounds read plus FSOP on musl mallocng internals. |

## Mobile

Android reversing, decompilation, and application behavior reconstruction.

| Challenge | Description |
|-----------|-------------|
| [avault](./avault/writeup/) | Decompiled Java analysis to recover logic and secrets. |
| [in-search-of-a-lost-note](./in-search-of-a-lost-note/writeup/) | Android reversing plus cryptographic procedure reconnaissance. |

## Network, AI, Misc, and Steganography

A mixed set that shows range: packet analysis, model-adjacent abuse, jail escapes, captcha bypasses, and media artifact analysis.

| Challenge | Category | Description |
|-----------|----------|-------------|
| [chimera-void](./chimera-void/writeup/) | Network | Traffic analysis and protocol-level artifact extraction. |
| [session-gpt](./session-gpt/writeup/) | ML/AI | Lateral movement driven by leaked JWTs and trust boundary mistakes. |
| [jail](./jail/writeup/) | Misc | Python jail escape through submodule discovery and runtime abuse. |
| [clanker-casino](./clanker-casino/writeup/) | Misc | Captcha bypass with pragmatic automation. |
| [echoes-of-the-past](./echoes-of-the-past/writeup/) | Stego | Metadata plus RMS-energy analysis to recover hidden signal. |

[Back to Home](../index.md)
