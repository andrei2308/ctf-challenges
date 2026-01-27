# Cryptography CTF Challenge: BabyEncryption

## Challenge Description
You are after an organised crime group which is responsible for the illegal weapon market in your country. As a secret agent, you have infiltrated the group enough to be included in meetings with clients. During the last negotiation, you found one of the confidential messages for the customer. It contains crucial information about the delivery. Do you think you can decrypt it?

## Files Provided

### chall.py
```python
import string
from secret import MSG

def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)

ct = encryption(MSG)
f = open('./msg.enc','w')
f.write(ct.hex())
f.close()
```

### msg.enc
```
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921
```

## Analysis

### Understanding the Encryption
Looking at the encryption function, we can see it performs the following operation on each character:
```
ciphertext = (123 * plaintext + 18) % 256
```

This is a simple **affine cipher** with:
- Multiplicative key: `123`
- Additive key: `18`
- Modulus: `256`

### Mathematical Approach
To decrypt, we need to reverse the encryption process:
1. Subtract the additive key: `(ciphertext - 18) % 256`
2. Multiply by the modular inverse of 123 modulo 256

The decryption formula becomes:
```
plaintext = ((ciphertext - 18) * inv(123)) % 256
```

### Finding the Modular Inverse
We need to find the modular inverse of 123 modulo 256 using the Extended Euclidean Algorithm.

## Solution

### Exploit Script
```python
#!/usr/bin/env python3

# Read the encrypted file
with open('msg.enc', 'r') as f:
    hex_data = f.read().strip()

ciphertext = bytes.fromhex(hex_data)
print(f"Ciphertext: {hex_data}")

# Find modular inverse of 123 mod 256 using Extended Euclidean Algorithm
def mod_inverse(a, m):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None
    return (x % m + m) % m

# Decrypt: pt = (ct - 18) * inv(123) mod 256
inv_123 = mod_inverse(123, 256)
print(f"Inverse of 123 mod 256: {inv_123}")

decrypted = []
for ct_byte in ciphertext:
    pt = ((ct_byte - 18) * inv_123) % 256
    decrypted.append(pt)

# Convert to string
flag = ''.join(chr(b) for b in decrypted)
print(f"\n*** FLAG: {flag} ***")
```

### Execution Process
1. **Read the encrypted data** from the hex file
2. **Calculate the modular inverse** of 123 modulo 256 using Extended Euclidean Algorithm
3. **Apply the decryption formula** to each byte of the ciphertext
4. **Convert the decrypted bytes** back to ASCII characters to reveal the flag

### Key Mathematical Concepts
- **Affine Cipher**: A type of substitution cipher using linear transformation
- **Modular Inverse**: Finding `x` such that `(123 * x) ≡ 1 (mod 256)`
- **Extended Euclidean Algorithm**: Used to find modular inverses when gcd(a,m) = 1

## Result
Running the exploit script successfully decrypts the message and reveals the flag containing the crucial delivery information the secret agent was looking for.

---

**Vulnerability Type:** Weak Cryptographic Implementation (Simple Affine Cipher)  
**Key Technique:** Modular Arithmetic and Inverse Calculation  
**Tools Used:** Python, Extended Euclidean Algorithm  