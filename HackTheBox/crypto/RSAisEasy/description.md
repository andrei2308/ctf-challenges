Here is a cleaned up, verified, and enhanced version of your description in proper Markdown format for use in a `description.md` file on GitHub:

---

# 🔐 Cryptography CTF Challenge: RSAisEasy

## 🧩 Challenge Description

> *"I think this is safe... Right?"*

Welcome to the **RSAisEasy** cryptography challenge. In this task, you're presented with an RSA-based encryption script and some output data. Your mission is to analyze and decrypt the given ciphertexts using insights from RSA vulnerabilities.

### 🧾 Given Data

You are provided with:

* `n1`: The modulus for the first ciphertext. As per RSA, `n1 = p * q`, where `p` and `q` are large primes.
* `c1`: The first encrypted part of the flag.
* `c2`: The second encrypted part of the flag.
* An interesting equation:

  ```
  combined = (n1 * E) + n2
  ```

  Here, `E` is a random 69-byte number, and `n2` is another RSA modulus. The value of `combined` is provided.

### 🔑 Known Facts

* The RSA exponent used is `e = 65536`, a common choice in RSA.
* The moduli `n1` and `n2` **share a common prime factor `q`**, meaning:

  ```
  gcd(n1, n2) = q
  ```

### 🧠 Strategy Overview

To decrypt the flags, we follow these steps:

1. **Recover `E`:**
   From the equation

   ```
   combined = (n1 * E) + n2
   ```

   we solve for `E`:

   ```
   E = combined // n1
   ```

2. **Recover `n2`:**
   Once `E` is known:

   ```
   n2 = combined - (n1 * E)
   ```

3. **Find the common factor `q`:**
   Since `n1` and `n2` share a factor:

   ```
   q = gcd(n1, n2)
   ```

4. **Factor `n1` and `n2`:**
   Knowing `q`, you can compute:

   ```
   p = n1 // q
   z = n2 // q
   ```

5. **Compute Euler's totient (`phi`) for both moduli:**

   ```
   phi1 = (p - 1) * (q - 1)
   phi2 = (z - 1) * (q - 1)
   ```

6. **Compute the private exponents `d1` and `d2`:**

   ```
   d1 = inverse(e, phi1)
   d2 = inverse(e, phi2)
   ```

7. **Decrypt the ciphertexts:**

   ```
   m1 = pow(c1, d1, n1)
   m2 = pow(c2, d2, n2)
   ```

8. **Recover the flag.**

---

### 📁 Files in This Repository

* `encrypt.py`: The RSA encryption script used in this challenge.
* `output.txt`: Contains `n1`, `c1`, `c2`, and `combined`.
* `solve.py`: Script that implements the above decryption steps.

---

### **Python Exploit Script**

Here’s the Python script to exploit the challenge:

```python
from math import gcd
from numpy import size  # Note: 'size' from numpy is imported but not used

def inverse(u, v):
    """Computes the modular inverse of u modulo v using the Extended Euclidean Algorithm."""
    if v == 0:
        raise ZeroDivisionError("Modulus cannot be zero")
    if v < 0:
        raise ValueError("Modulus cannot be negative")

    # Extended Euclidean Algorithm
    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    if u3 != 1:
        raise ValueError("No inverse value can be computed")
    while u1 < 0:
        u1 = u1 + v
    return u1

# Read values from output.txt
with open('output.txt', 'r') as f:
    lines = f.readlines()

# Parse the RSA parameters and combined value
n1 = int(lines[0].split(': ')[1])
c1 = int(lines[1].split(': ')[1])
c2 = int(lines[2].split(': ')[1])
combined = int(lines[3].split(': ')[1])

# Solve for E from the equation: combined = (n1 * E) + n2
E = combined // n1
n2 = combined - n1 * E  # Recover n2

# Find common factor q using GCD (since n1 and n2 share q)
gcd = gcd(n1, n2)
print(gcd)

# Factor n1 and n2 using q
z = n2 // gcd  # z is the other factor of n2
p = n1 // gcd  # p is the other factor of n1
print(z)
print(p)

# Compute private exponent for flag 1
phi1 = (p - 1) * (gcd - 1)
d1 = inverse(0x10001, phi1)  # Compute modular inverse of e mod phi1
flag1 = pow(c1, d1, n1)  # Decrypt flag1
flag1_bytes = flag1.to_bytes((flag1.bit_length() + 7) // 8, 'big')
print(flag1_bytes.decode())

# Compute private exponent for flag 2
phi2 = (z - 1) * (gcd - 1)
d2 = inverse(0x10001, phi2)
flag2 = pow(c2, d2, n2)  # Decrypt flag2
flag2_bytes = flag2.to_bytes((flag1.bit_length() + 7) // 8, 'big')
print(flag2_bytes.decode())

# Print the full flag
print(flag1_bytes.decode() + flag2_bytes.decode())
```

---

### 🚨 Vulnerability Exploited

This challenge highlights the dangers of **key reuse** and **shared primes** across different RSA keys. Once a common factor is found between two moduli, RSA's security is broken due to easy factorization.

---
