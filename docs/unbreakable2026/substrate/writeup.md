# Substrae — CTF Writeup

**Category:** Reverse Engineering  
**Flag:** `CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}`

---

## Summary

The challenge provided a Windows user-mode executable (`SubstrateUM.exe`) and a kernel driver (`SubstrateKM.sys`). The EXE was heavily obfuscated — IAT entries were swapped at runtime and all strings were built character-by-character through hash-based decode functions. I used Unicorn CPU emulation to recover the plaintext strings and understand the control flow: the app reads a flag, sends each byte to the driver via `DeviceIoControl` (IOCTL `0x228124`), then triggers verification (IOCTL `0x228128`). Analyzing the driver's verification handler revealed it processes input in 8 blocks of 9 bytes, performing a 3×3 upper-triangular matrix multiplication (mod 256) using the driver's own `DriverEntry` code bytes as key material, then comparing against hardcoded expected data. Since the key matrices are upper-triangular with odd diagonal elements (OR'd with 1), they are invertible mod 256. I extracted the key material from file offset `0x8E60` and the expected data from `0xA800`, computed the matrix inverses, and recovered the flag.

---

## Challenge Description

> I found this driver that was supposed to make my PC faster, but I haven't noticed anything different. The companion app seems to communicate with it somehow. These developers are making it harder and harder to reverse engineer their apps! Now I can't even attach a debugger without something breaking!

We're given three files:

- **SubstrateUM.exe** — A Windows user-mode console application
- **SubstrateKM.sys** — A Windows kernel-mode driver (KMDF)
- **SubstrateKM.inf** — Driver installation manifest

File identification:

```bash
file SubstrateUM.exe SubstrateKM.sys
# SubstrateUM.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
# SubstrateKM.sys: PE32+ executable (native) x86-64, for MS Windows, 7 sections

# Check PE sections and imports
python3 -c "
import pefile
pe = pefile.PE('SubstrateUM.exe')
for s in pe.sections:
    print(f'{s.Name.decode().strip(chr(0)):8s} VA=0x{s.VirtualAddress:x} Raw=0x{s.PointerToRawData:x} Size=0x{s.SizeOfRawData:x}')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for imp in entry.imports:
        print(f'  {imp.name.decode() if imp.name else hex(imp.ordinal)}')
"
```

## Overview

The user-mode app prompts for a flag, sends each byte to the kernel driver via `DeviceIoControl`, then asks the driver to verify. The driver performs a **3×3 upper-triangular matrix multiplication (mod 256)** using its own entry-point code bytes as key material and compares the result against a hardcoded expected buffer. To solve: extract the key matrix and expected data from the binary, invert the matrix, and recover the flag.

## Step 1 — Analyzing SubstrateUM.exe

### Anti-Debugging & Import Obfuscation

The executable contains several anti-reversing techniques:

- **IsDebuggerPresent** — The app checks for attached debuggers and exits/changes behavior.
- **IAT obfuscation** — Import table entries are swapped at runtime. For example, the IAT slot labeled `ExitProcess` actually resolves to `GetStdHandle` when called. We had to trace actual call arguments (e.g., `GetStdHandle(-11)` for stdout) to identify the real functions.

```bash
# List imports (will show misleading names due to IAT obfuscation)
python3 -c "
import pefile
pe = pefile.PE('SubstrateUM.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        print(f'0x{imp.address:x}  {imp.name.decode() if imp.name else "ord:"+str(imp.ordinal)}')
"
```

### Obfuscated String Construction

Every string is built character-by-character through individual calls to hash-based decode functions, each with unique constants. No plaintext strings appear in the binary.

```bash
# Confirm no plaintext strings
strings SubstrateUM.exe | grep -iE 'flag|correct|device'
# (no output — all strings are obfuscated)
```

Using Unicorn CPU emulation on each decode function, we recovered all strings:

```bash
python3 get_strings.py
```

| String | Purpose |
|--------|---------|
| `"Do you have the flag?\n"` | User prompt |
| `"Correct!"` | Success message |
| `"Maybe next time"` | Failure message |
| `"\\.\SubstrateDeviceLink"` | Device path |
| `"Error 1: "` through `"Error 7: "` | Error messages |

### Control Flow

1. Build prompt string → `GetStdHandle(stdout)` → `WriteConsoleA(prompt)`
2. `GetStdHandle(stdin)` → `ReadConsoleA(input, 69 bytes max)`
3. `CreateFileW("\\.\SubstrateDeviceLink")` → open handle to driver
4. Loop 69 times: send IOCTL `0x228124` with `[index, byte]` to store each input byte
5. Send IOCTL `0x228128` to trigger verification
6. Read result byte → print `"Correct!"` or `"Maybe next time"`

## Step 2 — Analyzing SubstrateKM.sys

### Device Setup

The driver creates device `\Device\SubstrateDevice` with symbolic link `\??\SubstrateDeviceLink`. It resolves kernel APIs dynamically via `MmGetSystemRoutineAddress` to hinder static analysis.

```bash
# Find driver entry point and string references
python3 -c "
import pefile
pe = pefile.PE('SubstrateKM.sys')
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f'DriverEntry RVA: 0x{ep:x}')
for s in pe.sections:
    print(f'{s.Name.decode().strip(chr(0)):8s} VA=0x{s.VirtualAddress:x} Raw=0x{s.PointerToRawData:x} Size=0x{s.SizeOfRawData:x}')
"

# Look for device name strings in the driver
strings -e l SubstrateKM.sys | grep -i substrate
# \Device\SubstrateDevice
# \??\SubstrateDeviceLink
```

### IOCTL Handlers

**IOCTL 0x228124** (at RVA `0x1919`): Stores a user-supplied byte at `ImageBase + 0xC5D8[index]`, where index must be < 0x48 (72). This is the input buffer.

**IOCTL 0x228128** (at RVA `0x177C`): The verification handler. This is where the core algorithm lives.

### The Core Algorithm — Matrix Multiplication

The verification handler processes the 72-byte input in **8 blocks of 9 bytes** each. For each block:

1. **Key construction**: A 3×3 upper-triangular matrix **K** is built from 9 consecutive bytes of the driver's own `DriverEntry` function code (at RVA `0x9A60`):

```
K = | code[0]|1   code[1]    code[2] |
    |    0     code[4]|1   code[5]  |
    |    0        0     code[8]|1   |
```

The diagonal elements are OR'd with 1 to guarantee they are odd (and thus invertible mod 256).

2. **Matrix-vector multiply**: The handler computes **K^T × v** (mod 256) for each of three 3-element sub-vectors in the 9-byte input block, where K^T is the transpose (lower triangular).

3. **Comparison**: Each result is compared against 9 bytes of expected data stored at RVA `0xC000` (file offset `0xA800`).

If all 72 bytes match, the driver returns success.

### Address Arithmetic Obfuscation

The IOCTL handler uses extremely convoluted address arithmetic involving stack-relative calculations. For example:

```asm
lea r12, [rsp + 0x28]
neg r12              ; r12 = -(rsp+0x28)
...
lea rdi, [rsp + 0x70]
sub rdi, 0x140009a60 ; rdi = rsp+0x70 - entry0_addr
```

These seemingly complex expressions cancel out during matrix element access, ultimately resolving to straightforward reads from the entry point code bytes and the user input buffer. This obfuscation makes dynamic analysis and emulation difficult.

## Step 3 — Solving

Since K^T is lower-triangular with odd diagonal elements, it's invertible mod 256. The flag is recovered as:

$$\mathbf{u} = (K^T)^{-1} \cdot \mathbf{e} \pmod{256}$$

where **e** is the expected data vector.

### Lower-Triangular Matrix Inverse

For each block's K^T matrix:

$$K^T = \begin{pmatrix} a & 0 & 0 \\ b & c & 0 \\ d & e & f \end{pmatrix}$$

The inverse mod 256 is:

$$(K^T)^{-1} = \begin{pmatrix} a^{-1} & 0 & 0 \\ -b \cdot a^{-1} c^{-1} & c^{-1} & 0 \\ (be-cd) \cdot a^{-1} c^{-1} f^{-1} & -e \cdot c^{-1} f^{-1} & f^{-1} \end{pmatrix} \pmod{256}$$

Since a, c, f are all odd (OR'd with 1), their modular inverses mod 256 exist.

### Key Material

Entry point bytes (8 blocks of 9, starting at file offset `0x8E60`):

```bash
# Extract key material (DriverEntry code bytes)
python3 -c "
with open('SubstrateKM.sys','rb') as f:
    data = f.read()
for i in range(8):
    block = data[0x8e60 + i*9 : 0x8e60 + (i+1)*9]
    print(f'Block {i}: {\" \".join(f\"{b:02x}\" for b in block)}')
"
```

Output:

```
Block 0: 48 89 5c 24 08 57 48 83 ec
Block 1: 20 48 8b da 48 8b f9 e8 8b
Block 2: 45 00 00 48 8b d3 48 8b cf
Block 3: e8 0c 00 00 00 48 8b 5c 24
Block 4: 30 48 83 c4 20 5f c3 cc 48
Block 5: 8b c4 48 89 58 08 48 89 68
Block 6: 10 48 89 70 18 48 89 78 20
Block 7: 41 56 48 83 ec 30 33 ed 48
```

### Expected Data

At file offset `0xA800`:

```bash
# Extract expected ciphertext
python3 -c "
with open('SubstrateKM.sys','rb') as f:
    data = f.read()
for i in range(8):
    block = data[0xa800 + i*9 : 0xa800 + (i+1)*9]
    print(f'Block {i}: {\" \".join(f\"{b:02x}\" for b in block)}')
"
```

Output:

```
Block 0: 1b cf 6e 13 8c 82 d4 8d d8
Block 1: 51 4c 4f 59 1e 48 d5 23 da
Block 2: af 52 c0 04 c7 29 7a c7 59
Block 3: d6 f8 4e ed f1 91 54 d6 ed
Block 4: 30 34 1e 25 ff c3 b8 f8 44
Block 5: 62 de 58 b1 79 82 68 9b 08
Block 6: 52 a2 d3 93 6a 6f b5 e0 6f
Block 7: 79 4a c0 34 e6 65 00 00 00
```

### Result

Inverting all 8 blocks and concatenating the recovered bytes (stripping trailing nulls):

```bash
python3 solver.py
```

Output:

```
=== Solving each block ===
Block 0: K^T = [0x49, 0, 0; 0x89, 0x09, 0; 0x5c, 0x57, 0xed]
  Vector 0: expected=['1b', 'cf', '6e'] → user=['43', '54', '46'] = CTF
  Vector 1: expected=['13', '8c', '82'] → user=['7b', '31', '63'] = {1c
  Vector 2: expected=['d4', '8d', 'd8'] → user=['34', '31', '65'] = 41e
...
=== FLAG ===
Printable: CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}
```

```
CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}
```

All 24 verification vectors (8 blocks × 3 sub-vectors) pass re-verification ✓.

## Tools Used

- **radare2** — Disassembly and static analysis
- **Python + pefile** — PE parsing and section mapping
- **Unicorn Engine** — CPU emulation for decoding obfuscated strings and partial IOCTL emulation
- **Capstone** — Disassembler library (auxiliary)
- **Manual analysis** — Tracing the convoluted address arithmetic in the IOCTL handler

```bash
pip install pefile unicorn capstone
```

## Solver Scripts

- [get_strings.py](get_strings.py) — Unicorn emulation of all EXE decode functions to reveal strings
- [emu_ioctl_handler.py](emu_ioctl_handler.py) — Unicorn emulation of driver IOCTL handler (partial, confirmed matrix multiply theory)
- [solver.py](solver.py) — Final mathematical solver: matrix inversion mod 256
