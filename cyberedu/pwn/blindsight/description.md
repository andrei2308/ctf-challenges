Here is the comprehensive writeup for the Blind ROP (BROP) challenge "Blindsight".

---

# Blindsight (BROP) Challenge Writeup

## Challenge Overview

**Type:** Blind ROP (Return Oriented Programming)
**Constraint:** No binary is provided.
**Goal:** We must probe the running service to reverse engineer its internal layout, find gadgets, leak memory, and eventually execute a shell.

The exploitation process follows the standard BROP methodology:

1. **Stack Smashing**: Find the buffer overflow offset.
2. **Stop Gadget**: Find an address that restarts the program (to prevent crashes).
3. **BROP Gadgets**: Find the `pop rdi; ret` gadget to control arguments.
4. **PLT Scan**: Find `puts@plt` to leak data.
5. **GOT Leak & Win**: Leak libc, calculate offsets, and call `system()`.

---

## Phase 1: Stack Layout & Stop Gadget

Before we can chain gadgets, we need to know two things: where the Return Instruction Pointer (RIP) is on the stack, and where to jump to keep the program alive.

### 1. Finding the Offset

By sending cyclic patterns, we identified that the application crashes after **88 bytes**.

* **Offset**: `88`

### 2. Finding the "Stop Gadget"

When we fuzz return addresses blindly, most addresses will cause a crash (EOF). However, valid addresses (like the `main` function or `_start`) will restart the service or print the welcome message again. This is our "Stop Gadget"—it acts as a safe landing pad for our ROP chains.

**Script Logic (`find_stop.py`):**
The script iterates through addresses starting at `0x400000` (standard non-PIE base).

* **Crash**: Connection closes -> Wrong address.
* **"blind" / "No password"**: Program restarted -> **Found Stop Gadget**.

**Result:** `0x4005c0` (Likely the address of `main`).

---

## Phase 2: Hunting BROP Gadgets

We need gadgets to pop arguments into registers (specifically `RDI` for function calls like `puts` or `system`). The best target in 64-bit binaries is `__libc_csu_init`, which contains a sequence of 6 pops:
`pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`

### Scanning Logic

We scan for this gadget using a specific stack layout:

1. **Probe Address**: The address we are testing.
2. **Traps**: 6 dummy values (e.g., `0xDEADBEEF`) to fill the registers if it is indeed a pop gadget.
3. **Stop Gadget**: If the pops succeed, the `ret` will jump here and restart the service.

* **If Address is NOT a gadget**: It crashes or halts.
* **If Address IS `pop x6; ret**`: It pops the 6 traps and successfully jumps to the Stop Gadget.

**Script Logic (`find_gadgets.py`):**
We scan from `0x4005c0`.

* Found Universal Gadget at: `0x4007ba`
* Derived `pop rdi; ret`: `0x4007ba + 9` = **`0x4007c3`**

---

## Phase 3: Finding `puts@plt`

Now we control `RDI` (first argument), but we need a function to print data. We scan the PLT region for `puts`.

### The Test

We construct a ROP chain that attempts to print the ELF header (`0x400000`) using every address in the PLT range.

* **Chain**: `pop rdi` -> `0x400000` -> `PROBE_ADDR` -> `STOP_GADGET`
* **Success Condition**: If we receive the bytes `\x7fELF`, then `PROBE_ADDR` is `puts@plt`.

**Script Logic (`find_puts.py`):**
The script threads connections to scan rapidly.
**Result:** `puts@plt` found at **`0x400550`**.

---

## Phase 4: Dumping the Binary (Optional)

With `puts` and a write primitive, we can dump the entire binary from memory to local disk to analyze it in Ghidra/IDA, though it's not strictly necessary if we just want to ROP.

**Script (`dump.py`):**
Reads memory page by page starting at `0x400000` and saves it to a file.

---

## Phase 5: Final Exploit (Ret2Libc)

We now have all the ingredients for a standard Ret2Libc attack.

1. **Leak GOT**: Use `puts` to print the address stored in `puts@got`.
2. **Calculate Libc**: Subtract the static offset of `puts` to find the libc base.
3. **Shell**: Calculate the address of `system` and `/bin/sh` and execute.

### Step 1: Verification & Leak

We first verify we can leak the machine code at `puts@plt` to calculate the GOT offset.

* **Leak**: Machine code `ff 25 xx xx xx xx` (JMP [RIP+offset]).
* **Calculation**: `puts@got` = `RIP` + `offset`.

### Step 2: The Attack Script (`rop.py`)

```python
# 1. Leak Libc Address
payload = b"A" * 88
payload += p64(pop_rdi)
payload += p64(puts_got)        # Arg: puts@got
payload += p64(puts_plt)        # Func: puts()
payload += p64(stop_gadget)     # Restart for second payload

# 2. Receive Leak & Calculate Base
# ... (recv and math) ...

# 3. Shell Payload
payload2 = b"A" * 88
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)         # Arg: "/bin/sh"
payload2 += p64(system)         # Func: system()

p.sendline(payload2)
p.interactive()

```

**Outcome:**
The script successfully leaks the libc version (likely `libc-2.23.so`), calculates the base, and pops a shell.