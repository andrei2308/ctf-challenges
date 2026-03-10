# Jumpy — Writeup

**Category:** Reverse Engineering (Hard)  
**Contest:** UNR26 Echipe — UNbreakable  
**Flag:** `UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}`

---

## Summary

I started by identifying the binary as a stripped ELF linked against `libcrypto.so.3` and noticing that `enc.sky` was exactly 96 bytes, suggesting 3 blocks of 32 bytes. Static analysis in Ghidra revealed that the binary derives a SHA-256 key from XORed `.rodata` constants, builds an RC4-like permutation table, then XOR-decrypts 14 self-modifying code stubs that form a state machine to transform input byte pairs into output. Rather than fully reversing every stub, I took a black-box approach: I fed controlled inputs into the binary and compared outputs, discovering that each input byte pair `(in[2k], in[2k+1])` is transformed independently of all other pairs. This meant I could brute-force each pair separately over the printable ASCII range (95×95 = 9,025 candidates). To further speed things up, I tested all 16 pair positions within a 32-byte block simultaneously in a single binary invocation — if a candidate pair `(a, b)` matched the target `enc.sky` bytes at any position, that pair was recorded. This reduced the total runs to roughly 27,000 across 3 blocks, completing in under 2 minutes and recovering the flag.

---

## Challenge Files

| File | Description |
|------|-------------|
| `chall` | ELF 64-bit x86-64 stripped binary (linked against `libcrypto.so.3`) |
| `enc.sky` | 96-byte ciphertext (the encrypted flag) |

File identification:

```bash
file chall
# chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=..., stripped

ldd chall
# libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3
# libc.so.6 => ...

wc -c enc.sky
# 96 enc.sky

xxd enc.sky | head
```

## Overview

The binary reads raw bytes from **stdin**, processes them through a **self-modifying code** state machine built from 14 encrypted code stubs, and writes the transformed result to `enc.sky`. The goal is to recover the input (flag) that produced the provided `enc.sky`.

## Analysis

### Binary Structure

Disassembly and decompilation were performed using Ghidra:

```bash
# Find main entry point
objdump -d chall | grep -A5 '<__libc_start_main>'

# Identify .rodata constants
readelf -S chall | grep rodata
objdump -s -j .rodata chall | head -30

# List dynamic symbols to confirm libcrypto usage
objdump -T chall | grep -i sha
# Shows references to SHA256_Init, SHA256_Update, SHA256_Final

# Dump the encrypted code stub region
objdump -d chall --start-address=0x401FD3 --stop-address=0x40274B | head -40
```

The binary's `main` function (at `0x4012f6`) performs the following:

1. **Seed derivation** — XORs constants from `.rodata` (`0x403060`, `0x403080`, `0x403090`) to build a seed, then computes `SHA-256(seed)` to derive a 32-byte digest.
2. **RC4-like state initialization** — Uses the SHA-256 digest to build a 256-byte permutation table (KSA phase of RC4).
3. **Code stub unmasking** — 14 code blocks (at addresses `0x401FD3`–`0x40274B`) are XOR-decrypted using a position-dependent key: `key = ((block_idx * 37) + (byte_pos * 13)) ^ 0xCB) & 0xFF`. The memory region is `mprotect`'d as RWX before unmasking.
4. **Input processing** — Reads up to 256 bytes from stdin, then processes them in **32-byte blocks** through the state machine.
5. **Output** — Writes the transformed buffer to `enc.sky`.

### The 14 Code Stubs

Each stub starts with `endbr64` and implements a different transformation step:

| Block | Function |
|-------|----------|
| 0 | Nibble swap + flag set |
| 1 | Store processed bytes to output buffer |
| 2 | Bounds check on counter |
| 3 | Counter advance + hash mixing |
| 4 | Load next byte pair from buffer |
| 5 | Dispatch via sub-state table |
| 6 | Multiplicative hash + rotate + conditional branch |
| 7 | OR/XOR/ADD with constants + branch |
| 8 | Conditional byte select + XOR/AND/shift mixing + multi-way branch |
| 9 | Shift-XOR + phase toggle |
| 10 | XOR with SHA-derived table byte |
| 11 | Rotate by SHA-table-derived amount + phase toggle |
| 12 | S-box (256-byte permutation table) lookup |
| 13 | OR 0xA5 + add 0x77 + XOR into rolling state + rotate left 3 |

The stubs are dispatched in a permuted order: `[2, 4, 5, 0, 1, 3, 6, 7, 10, 8, 9, 12, 11, 13]`.

### Key Observations

Discovering pair-wise independence — testing the same pair `(0x41, 0x42)` at position 0 against two different baseline contexts:

```bash
# Context 1: all-zeros baseline, pair (0x41,0x42) at position 0
printf '\x41\x42' | cat - /dev/zero | head -c 96 | ./chall
xxd enc.sky | head -1

# Context 2: all-0x42 baseline, same pair at position 0
printf '\x41\x42' | cat - <(python3 -c "import sys; sys.stdout.buffer.write(b'\x42'*94)") | ./chall
xxd enc.sky | head -1
# Both produce identical first two output bytes → pair-wise independent
```

Checking output length:

```bash
wc -c enc.sky
# 96   → 96 / 32 = 3 blocks
```

Debug mode:

```bash
X=1 ./chall < /dev/null
# Prints block metadata to stdout, skips writing enc.sky
```

1. **Pair-wise independence** — The transform operates on **input byte pairs** `(in[2k], in[2k+1])` independently, producing output byte pairs `(out[2k], out[2k+1])`. Changing one pair has no effect on any other pair's output.

2. **Context independence** — Each pair's output depends only on that pair's input values, not on any other bytes in the input. This was confirmed by testing the same pair values against different baseline contexts (all-zeros vs. all-0x42) and getting identical output pairs.

3. **Output structure** — For an input of length `n`, the output is `ceil(n / 32) * 32` bytes. The provided `enc.sky` is 96 bytes, meaning 3 blocks of 32 bytes.

4. **Debug mode** — Setting environment variable `X=1` activates a debug branch that prints block metadata to stdout and skips writing to `enc.sky`. This was initially misleading but confirmed the normal-mode output path.

## Solution

Given the pair-wise independence, the entire 256² = 65,536 search space per pair is tractable. Since pairs are independent, **all pairs within a block can be tested simultaneously** in a single binary invocation.

Save the original ciphertext before brute-forcing:

```bash
cp enc.sky enc.sky.bak
xxd enc.sky.bak
```

### Algorithm

```
For each candidate pair (a, b) in search space:
    Build a full input block with (a, b) at every pair position
    Run the binary once
    Check which pair positions now match the target enc.sky bytes
    Record matches
```

This reduces the search from 65,536 × 48 pairs = ~3.1M runs to just 65,536 × 3 blocks = ~196K runs. Further restricting the search space to printable ASCII (95 × 95 = 9,025 candidates) brings this down to **~27,000 runs** — completing in under 2 minutes.

### Implementation

```python
from pathlib import Path
import subprocess, os

work = Path('/home/cht2308/unbreakable/jumpy')
orig = work.joinpath('enc.sky').read_bytes()

def run_normal(data):
    (work / 'enc.sky').unlink(missing_ok=True)
    e = dict(os.environ); e.pop('X', None)
    subprocess.run(['./chall'], input=data, cwd=work,
                   capture_output=True, timeout=3, env=e)
    return (work / 'enc.sky').read_bytes()

# For each block (0, 1, 2), test all printable ASCII pairs
for block in range(3):
    offset = block * 32
    solutions = [None] * 16  # 16 pairs per 32-byte block
    for a in range(32, 127):
        for b in range(32, 127):
            inp = bytearray(96)
            # Set all 16 pair positions to (a, b) simultaneously
            for p in range(16):
                inp[block * 32 + p * 2] = a
                inp[block * 32 + p * 2 + 1] = b
            out = run_normal(bytes(inp))
            # Check each pair against target
            for p in range(16):
                oi = offset + p * 2
                if out[oi] == orig[oi] and out[oi+1] == orig[oi+1]:
                    solutions[p] = (a, b)
```

### Running the solver

```bash
chmod +x chall
python3 solve_jumpy.py
```

### Result

All pairs resolved to printable ASCII values, revealing the flag:

```
UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}
```

Verification — re-encrypt the recovered flag and compare:

```bash
echo -n 'UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}' | ./chall
diff enc.sky enc.sky.bak && echo 'Match!'
```

*(Romanian for roughly: "if you make the chall you're a boss and you stole 34 67 personal data, boss")*

## Key Takeaways

- **Self-modifying code** with XOR-encrypted stubs is a common obfuscation technique in RE challenges. Dumping and disassembling the decrypted stubs is essential.
- **Black-box differential analysis** (probing input/output relationships) can bypass the need to fully understand complex state machines. The critical insight was discovering that byte pairs are processed independently.
- **Parallelizing independent tests** (testing all 16 pairs in one run) reduced the search space by 16×, making brute-force feasible.
