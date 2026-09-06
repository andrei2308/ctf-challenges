#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, getPrime
from secrets import flag1, flag2
from os import urandom

flag1 = bytes_to_long(flag1)
flag2 = bytes_to_long(flag2)

p, q, z = [getPrime(512) for i in range(3)]

e = 0x10001 # = 65534

n1 = p * q # => q = n1/p
n2 = q * z # => q = n2/z

# n1/p = n2/z

c1 = pow(flag1, e, n1) # flag1^e % n1 = flag1^e % (p * q)
c2 = pow(flag2, e, n2) # flag2^3 % n2 = flag2^e % (q * z)

E = bytes_to_long(urandom(69))

print(f'n1: {n1}') # p * q
print(f'c1: {c1}') # flag 1 enc
print(f'c2: {c2}') # flag 2 enc
print(f'(n1 * E) + n2: {n1 * E + n2}') # E aflat si stim rezultatul

# n1 * E + n2 = x
# n2 = (n1 * E + n2) - n1 * E
# cmmdc intre n1 si n2 este q
