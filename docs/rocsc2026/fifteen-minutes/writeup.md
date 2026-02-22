# fifteenminutes — Crypto Writeup

**Category:** Crypto  
**Remote:** `nc 35.234.109.37 30351`  
**Flag:** `flag{ortho_lattice_ftw_56f17b85f9a3d5891b0f}`

## Overview

The server implements a custom RSA-like oracle with two challenge types, each running for 5 rounds. We have a 15-minute time limit (`signal.alarm(900)`) to solve all 10 rounds.

## Challenge Source

```python
bits = 1500
k = 3
rounds = 5

def chal(typ):
    for t in range(rounds):
        p = getPrime(bits)  # p ≢ 1 (mod 3)
        q = getPrime(bits)  # q ≢ 1 (mod 3)
        n = p * q
        m = randbelow(n)
        e = 3
        d = pow(e, -1, (p-1)*(q-1))

        if typ == 1: xp = d    # Signatures: res = (a*m + b)^d mod n
        else:        xp = e    # Encryption:  res = (a*m + b)^3 mod n

        for _ in range(50):
            s = input()
            if s == "E": break
            a = randbelow(2**100)
            b = randbelow(2**100)
            res = pow(a*m + b, xp, n)
            print(f"{res=}")

        if typ == 1:
            N = int(input("n="))
            assert N == n
        else:
            N = int(input("n="))
            M = int(input("m="))
            assert N == n and M == m
```

- **Type 1 (Signatures):** We get `res = (a*m + b)^d mod n` and must recover `n`.
- **Type 2 (Encryption):** We get `res = (a*m + b)^3 mod n` and must recover both `n` and `m`.

The coefficients `a, b` are random ~100-bit integers that we don't know, but they are small relative to the 3000-bit modulus `n`.

## Solution

### Part 1 — Recover n from Signatures (Type 1)

Each response is `res_i = (a_i * m + b_i)^d mod n`. Since `d` is the RSA private exponent with `e = 3`:

$$res_i^3 = (a_i \cdot m + b_i)^3 \mod n$$

but also:

$$res_i^3 = (a_i \cdot m + b_i)^3 + k_i \cdot n$$

for some integer $k_i$. Expanding the cube, each $Y_i = res_i^3$ is an integer that equals $(a_i m + b_i)^3$ **over the integers** plus a multiple of $n$.

The expanded cube $(am + b)^3 = a^3 m^3 + 3a^2 b m^2 + 3ab^2 m + b^3$ lies in a 3-dimensional subspace (spanned by the monomials $m^3, m^2, m, 1$ — but the coefficients $(a^3, 3a^2b, 3ab^2, b^3)$ lie on a twisted cubic, so effectively a 3D hidden structure plus a multiple of $n$ in each equation).

**Orthogonal lattice attack:**

We collect 15 values $Y_i = res_i^3$ and build the lattice:

$$M = \begin{pmatrix} I_{15} & Y \cdot \lambda \end{pmatrix}$$

where $\lambda$ is a large penalty (to force the LLL-reduced vectors to satisfy $\sum c_i Y_i = 0$). The short vectors in the kernel give integer relations among the $Y_i$. Since the hidden subspace is 3-dimensional, we find $15 - 3 = 12$ relations.

From the right kernel of these relations, we recover the 3D basis $U$. Then we solve $Y = c \cdot U$ over $\mathbb{Q}$ — the last coordinate's numerator gives $n$ (after stripping small prime factors).

### Part 2 — Recover n and m from Encryption (Type 2)

Each response is `res_i = (a_i * m + b_i)^3 mod n`. Unlike Type 1, we cannot cube these to "lift" above the modulus — the values are already cubed. The hidden structure is now 5-dimensional:

$$(a_i m + b_i)^3 = a_i^3 m^3 + 3a_i^2 b_i m^2 + 3a_i b_i^2 m + b_i^3 + k_i n$$

with unknowns $(a_i^3 m^3, \ldots, b_i^3, k_i n)$ forming a 5D subspace.

We collect 45 samples and compute the orthogonal lattice, yielding 5 basis vectors $U$. However, **LLL produces a skewed basis** — because one component (the $k_i n$ direction) is vastly larger than the others. Standard LLL cannot separate them.

**Algebraic Tensor Recovery:**

The coefficients $(a_i, b_i)$ satisfy the **Twisted Cubic** constraint: if we denote the 5 hidden components as $(t_i^3, t_i^2 s_i, t_i s_i^2, s_i^3, k_i n)$ (with $t_i = a_i m$, $s_i = b_i$), then any pair of components satisfies a quadratic relation.

We build a $45 \times 15$ matrix $Q$ where row $i$ contains all products $U_j[i] \cdot U_k[i]$ for $j \leq k$. The right kernel of $Q$ gives symmetric $5 \times 5$ matrices representing quadratic constraints. From 3 such kernel vectors, we identify the direction $v_K$ in the 5D space that corresponds to the $k_i n$ component.

**Quotient Lattice:**

We project out the $v_K$ direction:

$$P_T = \text{right\_kernel}([v_K])$$

and compute $W = P_T \cdot U$, then LLL-reduce. This gives a "clean" 4D lattice where each entry is $(a_i m + b_i)^3$ without the modular reduction noise.

**Cube root brute-force:**

We enumerate small integer combinations of the 4 LLL basis vectors (coefficients in $[-8, 8]$) and test whether all 45 components are perfect cubes. Using cubic residue pre-filtering modulo 64, 63, and 61, we quickly find two linearly independent vectors whose entries are all perfect cubes. Their cube roots give $(a_i m + b_i)$ for each sample.

**Resultants to recover n:**

For two independent vectors $\mathbf{a}$ and $\mathbf{b}$ of cube roots, each sample satisfies:

$$f_i(x) = (a_i x + b_i)^3 - Y_i = 0 \pmod{n}$$

where $x = m$. The resultant $\text{Res}(f_i, f_j)$ eliminates $x$ and produces a multiple of $n$. Taking $\gcd(\text{Res}(f_0, f_1), \text{Res}(f_0, f_2), \text{Res}(f_0, f_3))$ and stripping small factors recovers $n$.

**Polynomial GCD to recover m:**

Working in $\mathbb{Z}/n\mathbb{Z}[x]$, we compute $\gcd(f_0(x), f_1(x))$. Since both polynomials share the root $x = m$, their GCD is linear: $(x - m)$. The constant term gives $m$.

## Exploit

```python
from pwn import remote
import re
import itertools
from sage.all import *

def solve_orthogonal_lattice(Y, dim_hidden):
    N = len(Y)
    num_rels = N - dim_hidden
    M = Matrix(ZZ, N, N + 1)
    penalty = max(Y) * (2**2000)
    for i in range(N):
        M[i, i] = 1
        M[i, N] = Y[i] * penalty
    L = M.LLL()
    relations = [list(row[:N]) for row in L if row[N] == 0]
    relations.sort(key=lambda row: sum(x**2 for x in row))
    S = Matrix(ZZ, relations[:num_rels])
    U = Matrix(ZZ, S.right_kernel().basis()).LLL()
    U_list = list(U)
    U_list.sort(key=lambda v: sum(x**2 for x in v))
    return U_list

def exploit():
    io = remote("35.234.109.37", 30351)

    # === TYPE 1: Signatures (5 rounds) ===
    for round_idx in range(5):
        io.send(b"A\n" * 15 + b"E\n")
        Y = []
        for _ in range(15):
            res_line = io.recvline().decode()
            res = int(re.search(r"res=(\d+)", res_line).group(1))
            Y.append(res**3)

        U_list = solve_orthogonal_lattice(Y, dim_hidden=3)
        U_QQ = Matrix(QQ, U_list)
        Y_QQ = vector(QQ, Y)
        c = U_QQ.solve_left(Y_QQ)
        n = abs(c[-1].numerator())
        for p in primes(2, 1000):
            while n > 1 and n % p == 0: n //= p

        io.sendafter(b"n=", str(n).encode() + b"\n")

    # === TYPE 2: Encryption (5 rounds) ===

    # Precompute cubic residues for fast filtering
    valid_64 = [False]*64; valid_63 = [False]*63; valid_61 = [False]*61
    for x in range(64): valid_64[(x**3) % 64] = True
    for x in range(63): valid_63[(x**3) % 63] = True
    for x in range(61): valid_61[(x**3) % 61] = True

    for round_idx in range(5):
        io.send(b"A\n" * 45 + b"E\n")
        Y = []
        for _ in range(45):
            res_line = io.recvline().decode()
            res = int(re.search(r"res=(\d+)", res_line).group(1))
            Y.append(res)

        # Orthogonal lattice → 5D subspace
        U_list = solve_orthogonal_lattice(Y, dim_hidden=5)

        # Algebraic tensor recovery
        Q_rows = []
        for i in range(45):
            row = []
            for j in range(5):
                for k in range(j, 5):
                    row.append(U_list[j][i] * U_list[k][i])
            Q_rows.append(row)

        Q = Matrix(ZZ, Q_rows)
        K_basis = Q.right_kernel().basis()

        def vec_to_sym_mat(v):
            M = Matrix(QQ, 5, 5)
            idx = 0
            for j in range(5):
                for k in range(j, 5):
                    if j == k: M[j, k] = v[idx]
                    else: M[j, k] = v[idx] / 2; M[k, j] = v[idx] / 2
                    idx += 1
            return M

        M1 = vec_to_sym_mat(K_basis[0])
        M2 = vec_to_sym_mat(K_basis[1])
        M3 = vec_to_sym_mat(K_basis[2])

        Stack = Matrix(QQ, 15, 5)
        for i in range(5):
            for j in range(5):
                Stack[i, j] = M1[i, j]
                Stack[i+5, j] = M2[i, j]
                Stack[i+10, j] = M3[i, j]

        v_K_QQ = Stack.right_kernel().basis()[0]
        denom = lcm([x.denominator() for x in v_K_QQ])
        v_K_ZZ = vector(ZZ, [x * denom for x in v_K_QQ])
        g = gcd(list(v_K_ZZ))
        v_K = [int(x // g) for x in v_K_ZZ]

        # Quotient lattice — remove k*n direction
        P_T = Matrix(ZZ, [v_K]).right_kernel_matrix()
        U_mat = Matrix(ZZ, U_list)
        W_mat = P_T * U_mat
        L = W_mat.LLL()

        # Brute-force cube roots in the clean 4D lattice
        found_vectors = []
        W0 = L[0]; W1 = L[1]; W2 = L[2]; W3 = L[3]
        bound = 8

        for c0, c1, c2, c3 in itertools.product(range(-bound, bound+1), repeat=4):
            if c0 == c1 == c2 == c3 == 0: continue

            v0 = int(c0*W0[0] + c1*W1[0] + c2*W2[0] + c3*W3[0])
            if v0 <= 0: continue
            if not valid_64[v0 & 63]: continue
            if not valid_63[v0 % 63]: continue
            if not valid_61[v0 % 61]: continue
            r0, exact = ZZ(v0).nth_root(3, truncate_mode=True)
            if not exact: continue

            v1 = int(c0*W0[1] + c1*W1[1] + c2*W2[1] + c3*W3[1])
            if v1 <= 0: continue
            if not valid_64[v1 & 63]: continue
            if not valid_63[v1 % 63]: continue
            if not valid_61[v1 % 61]: continue
            r1, exact = ZZ(v1).nth_root(3, truncate_mode=True)
            if not exact: continue

            is_cube = True
            roots = [int(r0), int(r1)]
            for i in range(2, 45):
                val = int(c0*W0[i] + c1*W1[i] + c2*W2[i] + c3*W3[i])
                if val <= 0:
                    is_cube = False; break
                r, exact = ZZ(val).nth_root(3, truncate_mode=True)
                if not exact:
                    is_cube = False; break
                roots.append(int(r))

            if is_cube:
                is_indep = True
                for prev in found_vectors:
                    if roots[0] * prev[1] == roots[1] * prev[0]:
                        is_indep = False; break
                if is_indep:
                    found_vectors.append(roots)
                    if len(found_vectors) >= 2: break

        # Resultants → recover n
        valid_pair = None
        for a, b in itertools.permutations(found_vectors, 2):
            PR = PolynomialRing(ZZ, 'x')
            x = PR.gen()
            f0 = (a[0]*x + b[0])**3 - Y[0]
            f1 = (a[1]*x + b[1])**3 - Y[1]
            f2 = (a[2]*x + b[2])**3 - Y[2]
            f3 = (a[3]*x + b[3])**3 - Y[3]
            R01 = f0.resultant(f1)
            R02 = f0.resultant(f2)
            n_cand = gcd(R01, R02)
            if n_cand > 2**1000:
                R03 = f0.resultant(f3)
                n = abs(gcd(gcd(R01, R02), R03))
                valid_pair = (a, b)
                break

        a, b = valid_pair
        for p in primes(2, 10000):
            while n > 1 and n % p == 0: n //= p

        # Polynomial GCD → recover m
        PR_n = PolynomialRing(Zmod(n), 'xn')
        xn = PR_n.gen()
        f0_n = (a[0]*xn + b[0])**3 - Y[0]
        f1_n = (a[1]*xn + b[1])**3 - Y[1]
        poly_f = f0_n.monic()
        poly_g = f1_n.monic()
        while poly_g != 0:
            rem = poly_f % poly_g
            poly_f = poly_g
            if rem == 0: break
            poly_g = rem.monic()

        m_found = int(-poly_f[0])

        io.sendafter(b"n=", str(n).encode() + b"\n")
        io.sendafter(b"m=", str(m_found).encode() + b"\n")

    print(io.recvall(timeout=5).decode())

if __name__ == "__main__":
    exploit()
```

## Key Techniques

1. **Orthogonal Lattice:** Using LLL with a penalty column to find integer relations among the oracle outputs, then extracting the hidden subspace from the right kernel.

2. **Algebraic Tensor Recovery:** Exploiting the quadratic constraints of the Twisted Cubic structure to identify the "noise" direction ($k_i n$) in the 5D basis.

3. **Quotient Lattice:** Projecting out the noise direction to obtain a clean lattice where all entries are perfect cubes.

4. **Cubic Residue Filtering:** Pre-computing cubic residues modulo 64, 63, and 61 for rapid elimination of non-cube candidates during brute-force.

5. **Resultants:** Eliminating the unknown $m$ between pairs of polynomial equations to recover the modulus $n$.

6. **Polynomial GCD:** Computing $\gcd$ of two polynomials in $\mathbb{Z}/n\mathbb{Z}[x]$ to extract the shared root $m$.

## Flag

```
flag{ortho_lattice_ftw_56f17b85f9a3d5891b0f}
```
