
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