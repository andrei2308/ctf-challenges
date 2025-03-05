# Mathrix CTF Challenge Write-up

## Challenge Overview

In this challenge, we were presented with a cryptographic problem involving matrix encryption. The challenge provided two files:

1. `mathrix.sage` - The encryption/decryption script
2. `out.txt` - The output containing the encrypted flag and cryptographic parameters

The challenge description included a hint: "pff, who needs a finite body for sure? anyways," suggesting we need to think about the mathematical structure being used.

## Understanding the Encryption

Looking at the provided code in `mathrix.sage`, we can understand the encryption scheme:

```python
from secret import get_generator

p = random_prime(2^64)
A = get_generator(p)

flag = "CTF{...}"
assert flag.startswith("CTF{") and flag.endswith("}") and len(flag[4:-1]) == 64 and all(c in "0123456789abcdef" for c in flag[4:-1])

def encrypt(p, A, Ax, m):
    Zp = Zmod(p)
    M, A, Ax = matrix(Zp, 8, 8), matrix(Zp, A), matrix(Zp, Ax)
    assert len(m) <= 64
    for i in range(len(m)):
        row, col = divmod(i, 8)
        M[row, col] = ord(m[i])
    assert M.is_invertible()
    k = randrange(1, p)

    return A ** k, M * (Ax ** k)

def decrypt(p, x, Ak, C):
    Zp = Zmod(p)
    Ak, C = matrix(Zp, Ak), matrix(Zp, C)
    Akx = (Ak ** x).inverse()
    M = C * Akx
    dec = []
    for i in range(8):
        for j in range(8):
            if M[i,j] == 0:
                return "".join(dec)
            dec.append(chr(M[i,j]))
    return "".join(dec)

x = randrange(1, p)
Ax = A ** x

Ak, C = encrypt(p, A, Ax, flag[4:-1])

print("p =", p)
print("A =", list(A))
print("Ax =", list(Ax))
print("Ak =", list(Ak))
print("C =", list(C))
```

The key components:
- `p`: A random prime number
- `A`: A generator matrix
- `x`: A random exponent (the private key)
- `Ax`: The matrix `A^x` (can be viewed as the public key)
- `k`: Another random exponent used for encryption
- `Ak`: The matrix `A^k`
- `C`: The encrypted message

## Understanding the Problem

From the output file, we have all variables except `x`. To decrypt, we need to:
1. Find `x`
2. Compute `Akx = (Ak^x)^(-1)`
3. Calculate `M = C * Akx` to obtain the original message

The core challenge is finding `x`, which means solving a discrete logarithm problem: given `A` and `Ax = A^x`, find `x`.

## The Solution Approach

The key insight is that calculating discrete logarithms for matrices is computationally intensive, but we can simplify the problem. The hint in the challenge description ("pff, who needs a finite body for sure? anyways,") suggests we should consider transforming our problem into a more manageable form.

We can solve this by:

1. Finding the Jordan normal form of matrix `A`
2. Transforming both `A` and `Ax` into this form
3. Reducing the matrix discrete logarithm to scalar discrete logarithms, which are much easier to compute

### Mathematical Background

The Jordan normal form of a matrix `A` can be represented as:

```
J = P^(-1) * A * P
```

Where `P` is an invertible matrix and `J` is the Jordan normal form of `A`.

Once we have the transformation, we can apply:

```
J^x = P^(-1) * A^x * P
```

This means that finding `x` such that `A^x = Ax` is equivalent to finding `x` such that `J^x = P^(-1) * Ax * P`.

The beauty of the Jordan form is that it's essentially a block diagonal matrix, where each block is upper triangular. This makes the discrete logarithm calculation much simpler.

## Complete Exploit

The complete exploit can be found in this folder

## Executing the Solution

When running the exploit in SageMath, we get:

![alt text](image.png)

## Key Insights

1. The challenge illustrates the concept of matrix discrete logarithms
2. Jordan normal form provides a powerful tool to simplify matrix problems
3. The transformation reduced a complex matrix problem to simpler scalar computations
4. Understanding the mathematical structure of the problem is essential to finding an efficient solution

## Conclusion

This challenge demonstrated an interesting application of linear algebra and number theory in cryptography. By transforming the problem into Jordan normal form, we were able to efficiently solve what would otherwise be a computationally intensive discrete logarithm problem.

The key takeaway is that mathematical transformations can often simplify seemingly complex cryptographic challenges, making them tractable with the right approach.