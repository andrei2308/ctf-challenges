# CyberEDU

The broadest training-oriented section in the repository, with especially strong density in pwn. It works well as a progression path from fundamentals into more specialized binary exploitation techniques.

**27 Writeups** · Pwn Heavy · Crypto · Forensics · Web · Stego

---

## Cryptography

Foundational crypto challenges covering substitution, padding, and basic protocol mistakes.

| Challenge | Description |
|-----------|-------------|
| [Alice](./cryptography/Alice/description/) | Introductory cryptographic challenge with a clean solve path. |
| [super_caesar](./cryptography/super_caesar/description/) | Variant Caesar-style challenge with small twists in transformation logic. |
| [train-to-paddington](./cryptography/train-to-paddington/description/) | Padding-oracle style reasoning and ciphertext manipulation. |

## Forensics

Artifact inspection and host-level evidence recovery.

| Challenge | Description |
|-----------|-------------|
| [east](./forensics/east/description/) | Digital investigation with a focus on artifact discovery. |
| [victim](./forensics/victim/description/) | Incident analysis and reconstruction from available traces. |
| [zanger](./forensics/zanger/description/) | Forensic artifact extraction with a narrower evidence trail. |

## Misc

Small category, useful mainly as a break from the heavier binary and crypto material.

| Challenge | Description |
|-----------|-------------|
| [alien-console](./misc/alien-console/description/) | General challenge-solving with a less standard attack surface. |

## Pwn

Core of the CyberEDU section, ranging from format strings and canaries to heap primitives, TLS abuse, and VM-like targets.

| Challenge | Description |
|-----------|-------------|
| [baby-fmt](./pwn/baby-fmt/description/) | Format-string fundamentals and controlled memory disclosure. |
| [baby_rop](./pwn/baby_rop/description/) | ROP-oriented binary exploitation progression. |
| [bazooka](./pwn/bazooka/description/) | Binary analysis challenge with a stronger exploitation finish. |
| [blindsight](./pwn/blindsight/description/) | Blind ROP style exploitation under limited visibility. |
| [cache](./pwn/cache/description/) | Heap-oriented exploitation and allocator reasoning. |
| [can-you-jump](./pwn/can-you-jump/description/) | Control-flow redirection in a compact target. |
| [cookie](./pwn/cookie/description/) | Stack canary bypass and controlled execution flow. |
| [honeypot](./pwn/honeypot/description/) | Race condition and RNG prediction chained into exploitation. |
| [off](./pwn/off/description/) | Off-by-one bug with heap-side consequences. |
| [secret](./pwn/secret/description/) | Format string plus ROP chain construction. |
| [threadz](./pwn/threadz/description/) | TLS-oriented abuse and non-standard memory layout reasoning. |
| [virtual](./pwn/virtual/description/) | VM escape style target with out-of-bounds write potential. |
| [gentei](./pwn/gentei/description/) | House of spirit, BSS crawling, fastbin bypass, and hook overwrite. |

## Reverse Engineering

Smaller reversing section focused on logic recovery and puzzle structure.

| Challenge | Description |
|-----------|-------------|
| [mathematics](./rev_engineering/mathematics/description/) | Algorithm recovery through program inspection. |
| [strange-puzzle](./rev_engineering/strange-puzzle/description/) | Puzzle logic reconstruction from compiled behavior. |

## Steganography

Hidden-data extraction and media-based signal recovery.

| Challenge | Description |
|-----------|-------------|
| [coffee-time](./steganography/coffee-time/description/) | Hidden data extraction from a non-obvious carrier. |
| [flag-is-hidden](./steganography/flag-is-hidden/description/) | Steganographic recovery workflow with practical tooling. |

## Web

Smaller application-security subset focused on reconnaissance and protocol abuse.

| Challenge | Description |
|-----------|-------------|
| [http-for-pros](./web/http-for-pros/description/) | HTTP-layer exploitation with SSTI and payload construction. |
| [reccon](./web/reccon/description/) | Web reconnaissance and attack-surface mapping. |
| [ultra-crawl](./web/ultra-crawl/description/) | Crawling and automated analysis against a larger target surface. |

[Back to Home](../index.md)
