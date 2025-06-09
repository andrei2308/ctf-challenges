# Cryptography CTF Challenge: The Last Dance

## Challenge Description
To be accepted into the upper class of the Berford Empire, you had to attend the annual Cha-Cha Ball at the High Court. Little did you know that among the many aristocrats invited, you would find a burned enemy spy. Your goal quickly became to capture him, which you succeeded in doing after putting something in his drink. Many hours passed in your agency's interrogation room, and you eventually learned important information about the enemy agency's secret communications. Can you use what you learned to decrypt the rest of the messages?

## Files Provided

### source.py
```python
from Crypto.Cipher import ChaCha20
from secret import FLAG
import os

def encryptMessage(message, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=iv)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def writeData(data):
    with open("out.txt", "w") as f:
        f.write(data)

if __name__ == "__main__":
    message = b"Our counter agencies have intercepted your messages and a lot "
    message += b"of your agent's identities have been exposed. In a matter of "
    message += b"days all of them will be captured"
    
    key, iv = os.urandom(32), os.urandom(12)
    
    encrypted_message = encryptMessage(message, key, iv)
    encrypted_flag = encryptMessage(FLAG, key, iv)
    
    data = iv.hex() + "\n" + encrypted_message.hex() + "\n" + encrypted_flag.hex()
    writeData(data)
```

### out.txt
```
c4a66edfe80227b4fa24d431
7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990
7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7
```

## Vulnerability Analysis

### ChaCha20 Nonce Reuse
The critical vulnerability in this implementation is **nonce reuse**. Looking at the source code:

1. **Same key and nonce used**: Both the message and flag are encrypted with identical `key` and `iv` (nonce)
2. **Stream cipher vulnerability**: ChaCha20 is a stream cipher that generates a keystream based on key+nonce
3. **Identical keystreams**: Using the same key+nonce produces identical keystreams for both encryptions

### Mathematical Foundation
When the same keystream is used:
- `C1 = M1 ⊕ keystream` (encrypted_message)
- `C2 = M2 ⊕ keystream` (encrypted_flag)
- `C1 ⊕ C2 = M1 ⊕ M2`
- Therefore: `M2 = M1 ⊕ C1 ⊕ C2`

Since we know `M1` (the message), we can recover `M2` (the flag).

## Exploitation

### Attack Strategy
1. **Extract keystream** from known plaintext message
2. **Use keystream** to decrypt the flag
3. **Verify** using direct XOR method

### Exploit Script
```python
#!/usr/bin/env python3
"""
ChaCha20 Nonce Reuse Attack
Exploits the vulnerability where the same key+nonce is used for multiple encryptions
"""

def xor_bytes(a, b):
    """XOR two byte arrays"""
    return bytes(x ^ y for x, y in zip(a, b))

def attack_chacha20_nonce_reuse():
    """
    Exploit ChaCha20 nonce reuse vulnerability

    The vulnerability:
    - Same key+nonce used for encrypting both message and flag
    - This means same keystream is generated for both

    Attack:
    - C1 = M1 ⊕ keystream (encrypted_message)
    - C2 = M2 ⊕ keystream (encrypted_flag)
    - C1 ⊕ C2 = M1 ⊕ M2
    - Therefore: M2 = M1 ⊕ C1 ⊕ C2
    """

    print("=== ChaCha20 Nonce Reuse Attack ===")

    # Known plaintext message
    known_message = b"Our counter agencies have intercepted your messages and a lot "
    known_message += b"of your agent's identities have been exposed. In a matter of "
    known_message += b"days all of them will be captured"

    print(f"Known message length: {len(known_message)} bytes")
    print(f"Known message: {known_message}")

    try:
        # Read the output file
        with open("out.txt", "r") as f:
            lines = f.read().strip().split('\n')

        if len(lines) != 3:
            print(f"Error: Expected 3 lines in out.txt, got {len(lines)}")
            return

        iv_hex = lines[0]
        encrypted_message_hex = lines[1]
        encrypted_flag_hex = lines[2]

        print(f"\nIV: {iv_hex}")
        print(f"Encrypted message: {encrypted_message_hex}")
        print(f"Encrypted flag: {encrypted_flag_hex}")

        # Convert from hex to bytes
        iv = bytes.fromhex(iv_hex)
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        encrypted_flag = bytes.fromhex(encrypted_flag_hex)

        print(f"\nEncrypted message length: {len(encrypted_message)} bytes")
        print(f"Encrypted flag length: {len(encrypted_flag)} bytes")
        print(f"Known message length: {len(known_message)} bytes")

        # Verify message length matches
        if len(encrypted_message) != len(known_message):
            print(f"Warning: Length mismatch! encrypted_message={len(encrypted_message)}, known_message={len(known_message)}")

        # Method 1: Direct keystream recovery
        print(f"\n=== Method 1: Keystream Recovery ===")

        # Extract keystream from known message
        min_len = min(len(encrypted_message), len(known_message))
        keystream = xor_bytes(encrypted_message[:min_len], known_message[:min_len])

        print(f"Extracted keystream length: {len(keystream)} bytes")
        print(f"Keystream (first 32 bytes): {keystream[:32].hex()}")

        # Decrypt the flag using the keystream
        if len(encrypted_flag) <= len(keystream):
            decrypted_flag = xor_bytes(encrypted_flag, keystream[:len(encrypted_flag)])
            print(f"\nDECRYPTED FLAG: {decrypted_flag}")

            # Try to decode as text
            try:
                flag_text = decrypted_flag.decode('utf-8')
                print(f"FLAG (UTF-8): {flag_text}")
            except UnicodeDecodeError:
                print("Flag contains non-UTF-8 bytes")
        else:
            print(f"Error: Flag is longer than available keystream ({len(encrypted_flag)} > {len(keystream)})")

        # Method 2: Direct XOR approach
        print(f"\n=== Method 2: Direct XOR ===")

        # XOR the two ciphertexts to get M1 ⊕ M2
        min_len = min(len(encrypted_message), len(encrypted_flag))
        xor_result = xor_bytes(encrypted_message[:min_len], encrypted_flag[:min_len])

        # XOR with known message to get flag
        flag_len = min(len(xor_result), len(known_message))
        flag_candidate = xor_bytes(xor_result[:flag_len], known_message[:flag_len])

        print(f"Flag candidate (Method 2): {flag_candidate}")

        try:
            flag_text2 = flag_candidate.decode('utf-8')
            print(f"FLAG (Method 2): {flag_text2}")
        except UnicodeDecodeError:
            print("Flag candidate contains non-UTF-8 bytes")

        # If flag is longer than the message, try partial recovery
        if len(encrypted_flag) > len(known_message):
            print(f"\n=== Partial Flag Recovery ===")
            print(f"Flag is {len(encrypted_flag)} bytes, message is {len(known_message)} bytes")
            print(f"Can decrypt first {len(known_message)} bytes of flag")

            partial_flag = xor_bytes(encrypted_flag[:len(known_message)], keystream[:len(known_message)])
            print(f"Partial flag: {partial_flag}")

            try:
                partial_text = partial_flag.decode('utf-8')
                print(f"PARTIAL FLAG: {partial_text}")
            except UnicodeDecodeError:
                print("Partial flag contains non-UTF-8 bytes")

    except FileNotFoundError:
        print("Error: out.txt file not found!")
        print("Make sure you have the output file from the ChaCha20 encryption")
    except Exception as e:
        print(f"Error: {e}")

def main():
    attack_chacha20_nonce_reuse()

if __name__ == "__main__":
    main()
```

## Attack Process

### Step 1: Parse the Output
The `out.txt` file contains three lines:
1. **IV (nonce)**: `c4a66edfe80227b4fa24d431`
2. **Encrypted message**: Known plaintext encrypted
3. **Encrypted flag**: Target to decrypt

### Step 2: Keystream Extraction
Using the known plaintext message:
```python
keystream = encrypted_message ⊕ known_message
```

### Step 3: Flag Decryption
Apply the extracted keystream to the encrypted flag:
```python
flag = encrypted_flag ⊕ keystream
```

### Step 4: Verification
Use the direct XOR method as verification:
```python
flag = known_message ⊕ encrypted_message ⊕ encrypted_flag
```

## Key Insights

### Why This Attack Works
1. **Deterministic keystream**: ChaCha20 with same key+nonce always produces identical keystream
2. **Known plaintext**: We have the exact message that was encrypted
3. **Stream cipher property**: XOR operations are reversible when keystream is known

### Critical Mistake in Code
The bug is in the `encryptMessage` function:
```python
def encryptMessage(message, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=iv)  # Should use 'nonce' parameter
```

The function parameter is `nonce` but uses global `iv`, causing both encryptions to use the same nonce.

---

**Vulnerability Type:** Nonce Reuse in Stream Cipher  
**Cipher Affected:** ChaCha20  
**Attack Method:** Known Plaintext + Keystream Recovery  
**Key Technique:** XOR Properties of Stream Ciphers  