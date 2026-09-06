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