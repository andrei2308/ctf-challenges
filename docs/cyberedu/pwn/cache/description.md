
---

# CTF Challenge Writeup

## Vulnerability Analysis

The vulnerability is a **Double Free** and **Use-After-Free (UAF)** caused by the improper handling of the `input_buffer` pointer.

In the menu loop:

1. **Option 2 (`Make new user`)**: Allocates 16 bytes to `input_buffer`.
2. **Option 7 (`Delete user`)**: Frees `input_buffer` but **does not set the pointer to NULL**.

```c
else if (menu_input == 7) {
  free(input_buffer); // Pointer remains dangling
}

```

Since the pointer is not cleared:

* We can free it again (Double Free).
* We can write to it using **Option 4 (`Edit Student Name`)** even after it is freed (UAF).

## Exploit Steps

The target environment uses `glibc 2.27`, which allows for Tcache poisoning via double frees without modern checks.

### 1. Tcache Poisoning (Double Free)

We allocate a chunk and free it twice to create a recursive loop in the tcache bin.

* `Make new user` (Alloc Chunk A)
* `Delete user` (Free A)
* `Delete user` (Free A)

**Tcache State:** `Chunk A -> Chunk A`

### 2. Arbitrary Address Write Setup

We use the UAF (Option 4) to modify the `fd` pointer of the freed Chunk A to point to the Global Offset Table (GOT) entry for `free`.

* `Edit Student Name`: Overwrite content with address of `free@got`.

**Tcache State:** `Chunk A -> free@got`

### 3. Pointing to GOT

We allocate two chunks. The first consumes Chunk A, and the second returns the address we injected (`free@got`).

* `Make new user` (Consumes Chunk A)
* `Make new user`: Consumes `free@got`. The global `input_buffer` now points directly to the `free` function pointer in the GOT.
* *Note:* This step forces a write. We write a single byte (`\x41`) to minimize corruption, only changing the Least Significant Byte (LSB) of the `free` address.



### 4. Libc Leak & Repair

Since `input_buffer` points to `free@got`, we can read it to leak the libc address.

* `Print Student Name`: Reads the address stored at `free@got`.
* **Repair Logic:** Because the previous step corrupted the LSB with `0x41`, we calculate the base address by masking off the LSB of the leak and restoring it using the static symbol offset from the provided libc.

### 5. Overwrite & Win

With the libc base calculated and `input_buffer` still pointing to `free@got`, we overwrite `free` with a `one_gadget`.

* `Edit Student Name`: Write the address of `one_gadget`.
* `Delete user`: Calls `free()`. Since the GOT is hijacked, this triggers the `one_gadget` and spawns a shell.