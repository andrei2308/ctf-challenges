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
* `solve.py`: (To be created by you) Script that implements the above decryption steps.

---

### 🚨 Vulnerability Exploited

This challenge highlights the dangers of **key reuse** and **shared primes** across different RSA keys. Once a common factor is found between two moduli, RSA's security is broken due to easy factorization.

---