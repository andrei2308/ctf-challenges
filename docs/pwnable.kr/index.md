# pwnable.kr

A progression-oriented archive of classic binary exploitation problems. This section works best as a structured path from introductory memory corruption into multi-step input, architecture, and ROP challenges.

**10 Writeups** · Beginner · Intermediate · Advanced · Binary Exploitation

---

## Beginner Level

First-contact problems for memory corruption, validation bugs, and simple program logic attacks.

| Challenge | Description |
|-----------|-------------|
| [Buffer Overflow](./pwnable-bufferOverflow/description/) | Classic stack overwrite challenge and exploitation baseline. |
| [Collision](./pwnable-collisions/description/) | Hash collision reasoning in a compact challenge setup. |
| [fd](./pwnable-fd/description/) | File-descriptor confusion and process I/O behavior. |
| [Flag](./pwnable-flag/description/) | Basic reverse engineering with a lighter binary analysis path. |
| [Passcode](./pwnable-passcode/description/) | Format-string vulnerability and state corruption. |

## Intermediate Level

More interesting input surfaces and architecture-specific reasoning.

| Challenge | Description |
|-----------|-------------|
| [Random](./pwnable-random/description/) | Predictable randomness turned into exploit leverage. |
| [Input](./pwnable-input/description/) | Multi-vector input validation and environment control. |
| [Leg](./pwnable-leg/description/) | ARM assembly analysis and low-level behavior tracing. |

## Advanced Level

Later-stage challenges built around ROP, probability abuse, and more careful control-flow planning.

| Challenge | Description |
|-----------|-------------|
| [HorCruxes](./pwnable-horcruxes/description/) | Return-oriented programming with a more structured chain. |
| [Lotto](./pwnable-lotto/description/) | Probability manipulation and repeated-state abuse. |

[Back to Home](../index.md)
