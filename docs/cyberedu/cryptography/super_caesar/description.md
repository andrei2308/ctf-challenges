
## Challenge: Super Caesar
**Type:** Cryptography

### Initial Analysis
We're given an encrypted message with three distinct parts:
```
bcjac ---YnuNmQPGhQWqCXGUxuXnFVqrUVCUMhQdaHuCIrbDIcUqnKxbPORYTzVCDBlmAqtKnEJcpED --- UVQR
```

The challenge name suggests this involves Caesar cipher variations.

### Step 1: Analyze the Boundary Markers
Looking at the first and last parts:
- `bcjac` → appears to be "start" shifted
- `UVQR` → appears to be "STOP" shifted

### Step 2: Determine Shift Values
Through trial or frequency analysis:
- **bcjac**: "start" shifted **17 positions forward**
  - To decrypt: shift **9 positions backward** (26 - 17 = 9)
- **UVQR**: "STOP" shifted **24 positions forward** 
  - To decrypt: shift **2 positions backward** (26 - 24 = 2)

### Step 3: Key Observation
The crucial insight is that:
- Lowercase letters use a **9-position shift**
- Uppercase letters use a **2-position shift**

### Step 4: Solution Implementation
```python
def main():
    s = bytearray(b'bcjac --- YnuNmQPGhQWqCXGUxuXnFVqrUVCUMhQdaHuCIrbDIcUqnKxbPORYTzVCDBlmAqtKnEJcpED --- UVQR')
    
    # Split the message into three parts
    k1, s, k2 = s.split(b' --- ')
    
    # Decrypt the middle section with different shifts based on case
    for i in range(len(s)):
        c = s[i]
        if 65 <= c <= ord('Z'):  # Uppercase letters
            c = 65 + ((c - 65) - 2) % 26  # Shift back by 2
        else:  # Lowercase letters
            c = 97 + ((c - 97) - 9) % 26  # Shift back by 9
        s[i] = c
    
    print(s.decode())

if __name__ == '__main__':
    main()
```

### Step 5: Result
Running the script reveals the decrypted flag.

### Key Learning Points:
1. **Multi-shift Caesar ciphers** - Different parts of text can use different shift values
2. **Case sensitivity in cryptography** - Uppercase and lowercase letters may have different treatments
3. **Boundary analysis** - Start/stop markers often provide clues about the encryption method
4. **Modular arithmetic** - Using `% 26` to handle alphabet wrapping

### Alternative Analysis Method:
```python
# Quick shift testing for boundary words
def test_shifts(word, target):
    for shift in range(26):
        decoded = ''.join(chr((ord(c) - ord('a') - shift) % 26 + ord('a')) for c in word.lower())
        if decoded == target:
            print(f"'{word}' -> '{target}' with shift {shift}")
            return shift

# test_shifts('bcjac', 'start') → shift 17
# test_shifts('uvqr', 'stop') → shift 24
```

This challenge demonstrates how Caesar ciphers can be made more complex by using multiple shift values within the same message!