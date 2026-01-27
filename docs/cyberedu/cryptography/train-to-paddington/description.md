# Train-to-Paddington CTF Challenge Writeup

## Challenge Information
- **Name:** train-to-paddington
- **Description:** The train to Paddington is leaving soon! Will you be able to find your ticket ID in time? Why did you encrypt it without storing the password...?
- **Category:** Cryptography

## Initial Analysis

We're given a Python encryption script and a ciphertext file:

```python
import os

BLOCK_SIZE = 16
FLAG = b'|||REDACTED|||'

def pad_pt(pt):
    amount_padding = 16 if (16 - len(pt) % 16) == 0 else 16 - len(pt) % 16
    return pt + (b'\x3f' * amount_padding)

pt = pad_pt(FLAG)
key = os.urandom(BLOCK_SIZE)

ct = b''
j = 0
for i in range(len(pt)):
    ct += (key[j] ^ pt[i]).to_bytes(1, 'big')
    j += 1
    j %= 16

with open('output.txt', 'w') as f:
    f.write(ct.hex())
```

### Understanding the Encryption

1. **Padding Scheme:** The plaintext is padded with `0x3f` bytes (`?` characters) to make the length a multiple of 16
2. **Key:** A random 16-byte key is generated
3. **Encryption Method:** Simple XOR cipher where each plaintext byte is XORed with a repeating 16-byte key
4. **Formula:** `ct[i] = pt[i] ^ key[i % 16]`

### Ciphertext
```
b4b55c3ee34fac488ebeda573ab1f974bf9b2b0ee865e45a92d2f14b7bdabb6ed4872e4dd974e803d9b2ba1c77baf725
```

Length: 48 bytes (0x30 in hex)

## Vulnerability Analysis

This encryption scheme has a critical weakness: **known plaintext in the padding**.

### The Attack Vector

Since we know:
- The padding bytes are `0x3f`
- The key repeats every 16 bytes
- We can calculate: `key[i % 16] = ct[i] ^ pt[i]`

If we can identify which bytes are padding, we can recover the corresponding key bytes!

### Key Recovery Strategy

1. **From Padding:** XOR ciphertext padding bytes with `0x3f` to get key bytes
2. **From Flag Format:** The flag starts with `TFCCTF{`, giving us more known plaintext
3. **Combine:** Use both sources to recover all 16 key bytes

## Solution

### Step 1: Determine Padding Length

The ciphertext is 48 bytes. We need to figure out how many are padding.

Since padding follows the rule: `padding_len = 16 - (flag_len % 16)` or 16 if already aligned, we need to try different possibilities.

### Step 2: Exploit Known Plaintext

We know:
- Flag starts with `TFCCTF` (6 bytes)
- Padding bytes are `0x3f`

### Step 3: Exploitation Script

```python
ciphertext = "b4b55c3ee34fac488ebeda573ab1f974bf9b2b0ee865e45a92d2f14b7bdabb6ed4872e4dd974e803d9b2ba1c77baf725"
ct = bytes.fromhex(ciphertext)

prefix = b'TFCCTF'

# Recover first 6 key bytes from the known prefix
key = [None] * 16

for i in range(len(prefix)):
    key[i] = ct[i] ^ prefix[i]

# Try different padding lengths to recover the rest of the key
for padding_len in range(1, 17):
    test_key = key.copy()
    start = 48 - padding_len
    
    # Recover key bytes from padding
    for i in range(start, 48):
        test_key[i % 16] = ct[i] ^ 0x3f
    
    # Check if we have full key (no None values)
    if None not in test_key:
        # Decrypt
        pt = bytes([ct[i] ^ test_key[i % 16] for i in range(len(ct))])
        try:
            flag = pt.decode('ascii')
            if flag.startswith('TFCCTF') and flag.isprintable():
                print(f"Padding length: {padding_len}")
                print(f"Recovered key: {bytes(test_key).hex()}")
                print(f"Flag: {flag}")
                break
        except:
            pass
```

### Step 4: Execute and Capture the Flag

Running the exploit reveals:
- The correct padding length
- The recovered 16-byte key
- The decrypted flag

## Key Takeaways

### Why This Attack Works

1. **Repeating Key:** XOR with a repeating key is weak - once you know any key byte, you can decrypt all bytes at that position modulo 16
2. **Known Plaintext:** The padding scheme uses a fixed, known byte value
3. **Flag Format:** CTF flags typically have predictable prefixes, providing additional known plaintext

### Lessons Learned

- Never use a simple repeating XOR for encryption
- Known padding patterns can leak key material
- Predictable plaintext (like flag formats) enables known plaintext attacks
- Proper encryption requires: authenticated encryption modes (like AES-GCM), random IVs, and no key reuse

### Better Alternatives

Instead of this scheme, use:
- **AES in GCM or CBC mode** with proper IV handling
- **Standard padding schemes** like PKCS#7 with authenticated encryption
- **Never reuse keys** or use predictable padding patterns

## Flag

`TFCCTF{...}` (redacted - solve it yourself! 🚂)

---

**Challenge Rating:** Medium  
**Skills Required:** Understanding of XOR properties, known plaintext attacks, basic cryptanalysis  
**Tools Used:** Python 3, basic crypto knowledge