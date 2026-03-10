# Unbreakable 2026

Selected writeups from the Unbreakable qualification phase, with the strongest material concentrated in reverse engineering, web exploitation, threat hunting, and low-level memory corruption.

**9 Writeups** · Reverse Engineering · Web · Threat Hunting · Pwn

---

## Forensics and Cryptography

Challenge recoveries focused on evidence extraction, encrypted artifacts, and post-incident reconstruction.

| Challenge | Description |
|-----------|-------------|
| [Tokio Magic](./tokio-magic/writeup/) | Encrypted file recovery with a practical incident-response angle. |
| [Ram Vault Beacon Malware](./ram-vault-beacon-malware/writeup/) | Memory dump analysis for malware behavior and artifact extraction. |

## Web

Input filter bypasses, browser-side execution chains, and race-condition driven exploitation.

| Challenge | Description |
|-----------|-------------|
| [demolition](./demolition/writeup/) | Filter bypass leading into script execution and a cleaner XSS chain. |
| [minegamble](./minegamble/writeup/) | Race condition abuse paired with client-side injection. |
| [svfgp](./svfgp/writeup/) | Timing-sensitive XSS with a more careful exploitation path than a simple payload drop. |

## Threat Hunting

Alert triage and evidence-driven investigation from telemetry, logs, and event timelines.

| Challenge | Description |
|-----------|-------------|
| [control](./control/writeup/) | Alert analysis with emphasis on signal extraction over noise. |
| [unholy-land](./unholy-land/writeup/) | Event analysis and correlation across suspicious activity traces. |

## Pwn

Memory corruption with a smaller count here, but higher density in technique and exploit detail.

| Challenge | Description |
|-----------|-------------|
| [atypical-heap-reevenge](./atypical-heap-reevenge/writeup/) | Out-of-bounds read, metadata corruption, and an eventual arbitrary read-write primitive. |

## Reverse Engineering

The strongest section in this event, ranging from custom crypto analysis to heavily obfuscated Windows binaries.

| Challenge | Description |
|-----------|-------------|
| [jumpy](./jumpy/writeup/) | Custom encryption reversal with a clearer dataflow reconstruction. |
| [substrate](./substrate/writeup/) | Obfuscated Windows binary and driver analysis with dynamic string recovery and matrix inversion. |
| [the-flag-is-a-lie](./the-flag-is-a-lie/writeup/) | Unity game reverse engineering with asset and logic inspection. |

[Back to Home](../index.md)
