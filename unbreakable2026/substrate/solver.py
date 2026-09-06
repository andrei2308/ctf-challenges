#!/usr/bin/env python3
"""
Final solver for Substrate CTF challenge.

The IOCTL 0x228128 handler in SubstrateKM.sys:
1. Constructs a 3x3 upper triangular key matrix K from entry0 code bytes
2. Computes K^T * user_input for each 3-vector in the 9-byte block
3. Compares with expected data at 0xc000

To solve: user_input = (K^T)^(-1) * expected (mod 256)

For each of 8 blocks (i=0..7):
  Code bytes: entry0[i*9 .. i*9+8]
  K = upper triangular:
    K[0,0] = code[0] | 1    K[0,1] = code[1]    K[0,2] = code[2]
    K[1,0] = 0               K[1,1] = code[4]|1  K[1,2] = code[5]
    K[2,0] = 0               K[2,1] = 0           K[2,2] = code[8]|1
  
  The matrix multiply uses K transposed (lower triangular):
    K^T = [[a, 0, 0], [b, c, 0], [d, e, f]]
    where a = code[0]|1, b=code[1], c=code[4]|1, d=code[2], e=code[5], f=code[8]|1
  
  result[j*3+k] = sum(K^T[k,m] * user[j*3+m] for m=0..2) for j=0..2, k=0..2
  
  To invert (lower triangular inverse mod 256):
    user = (K^T)^(-1) * expected
"""

def mod_inv(x, m=256):
    """Compute modular inverse of x mod m using extended GCD."""
    if x % 2 == 0:
        return None  # No inverse for even numbers mod 256
    # Extended Euclidean algorithm
    g, a, _ = extended_gcd(x % m, m)
    if g != 1:
        return None
    return a % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def invert_lower_triangular_3x3(L):
    """Invert a 3x3 lower triangular matrix mod 256.
    L = [[a, 0, 0], [b, c, 0], [d, e, f]]
    L^(-1) = [[1/a, 0, 0], [-b/(ac), 1/c, 0], [(be-cd)/(acf), -e/(cf), 1/f]]
    """
    a, b, c, d, e, f = L[0][0], L[1][0], L[1][1], L[2][0], L[2][1], L[2][2]
    
    inv_a = mod_inv(a)
    inv_c = mod_inv(c)
    inv_f = mod_inv(f)
    
    if inv_a is None or inv_c is None or inv_f is None:
        print(f"ERROR: Cannot invert! a={a:#x}, c={c:#x}, f={f:#x}")
        return None
    
    # L^(-1)[0][0] = 1/a
    r00 = inv_a
    # L^(-1)[1][0] = -b/(ac) = -b * inv_a * inv_c
    r10 = (-b * inv_a * inv_c) % 256
    # L^(-1)[1][1] = 1/c
    r11 = inv_c
    # L^(-1)[2][0] = (be - cd) / (acf) = (b*e - c*d) * inv_a * inv_c * inv_f
    r20 = ((b * e - c * d) * inv_a * inv_c * inv_f) % 256
    # L^(-1)[2][1] = -e/(cf) = -e * inv_c * inv_f
    r21 = (-e * inv_c * inv_f) % 256
    # L^(-1)[2][2] = 1/f
    r22 = inv_f
    
    return [[r00, 0, 0], [r10, r11, 0], [r20, r21, r22]]

def mat_vec_mul_mod256(M, v):
    """Multiply 3x3 matrix M by 3-vector v, mod 256."""
    result = [0, 0, 0]
    for i in range(3):
        s = 0
        for j in range(3):
            s += M[i][j] * v[j]
        result[i] = s % 256
    return result

# Load the driver binary
with open("SubstrateKM.sys", "rb") as f:
    sys_data = f.read()

# Entry0 is at RVA 0x9a60, file offset = 0x9a60 - 0x1000 + 0x400 = 0x8e60
# .text section: VA=0x1000, RawOff=0x400
entry0_file_offset = 0x400 + (0x9a60 - 0x1000)
entry0_bytes = sys_data[entry0_file_offset:entry0_file_offset + 72]

# Expected data at RVA 0xc000, file offset = 0xc000 - 0xc000 + 0xa800 = 0xa800
# .data section: VA=0xc000, RawOff=0xa800
expected_data = sys_data[0xa800:0xa800 + 72]

print("=== Entry0 code bytes (key material) ===")
for i in range(8):
    block = entry0_bytes[i*9:(i+1)*9]
    print(f"  Block {i}: {' '.join(f'{b:02x}' for b in block)}")

print("\n=== Expected data at 0xc000 ===")
for i in range(8):
    block = expected_data[i*9:(i+1)*9]
    print(f"  Block {i}: {' '.join(f'{b:02x}' for b in block)}")

# Solve for each block
flag_bytes = []

print("\n=== Solving each block ===")
for i in range(8):
    code = entry0_bytes[i*9:(i+1)*9]
    exp = list(expected_data[i*9:(i+1)*9])
    
    # Build K^T (lower triangular)
    a = code[0] | 1
    b = code[1]
    c = code[4] | 1
    d = code[2]
    e = code[5]
    f = code[8] | 1
    
    KT = [[a, 0, 0], [b, c, 0], [d, e, f]]
    print(f"\nBlock {i}: K^T = [{a:#04x}, 0, 0; {b:#04x}, {c:#04x}, 0; {d:#04x}, {e:#04x}, {f:#04x}]")
    
    # Invert K^T
    KT_inv = invert_lower_triangular_3x3(KT)
    if KT_inv is None:
        print(f"  ERROR: Cannot invert block {i}")
        flag_bytes.extend([0] * 9)
        continue
    
    # Solve for each 3-vector in the block
    for j in range(3):
        exp_vec = exp[j*3:(j+1)*3]
        user_vec = mat_vec_mul_mod256(KT_inv, exp_vec)
        flag_bytes.extend(user_vec)
        print(f"  Vector {j}: expected={[f'{b:02x}' for b in exp_vec]} → user={[f'{b:02x}' for b in user_vec]} = {''.join(chr(b) if 32 <= b < 127 else '.' for b in user_vec)}")

# Verify the solution
print("\n=== Verification ===")
for i in range(8):
    code = entry0_bytes[i*9:(i+1)*9]
    a = code[0] | 1
    b = code[1]
    c = code[4] | 1
    d = code[2]
    e = code[5]
    f = code[8] | 1
    KT = [[a, 0, 0], [b, c, 0], [d, e, f]]
    
    for j in range(3):
        user_vec = flag_bytes[i*9+j*3:i*9+j*3+3]
        result = mat_vec_mul_mod256(KT, user_vec)
        exp_vec = list(expected_data[i*9+j*3:i*9+j*3+3])
        match = "✓" if result == exp_vec else "✗"
        print(f"  Block {i} Vec {j}: KT*user={[f'{b:02x}' for b in result]} vs expected={[f'{b:02x}' for b in exp_vec]} {match}")

# Print the flag
print(f"\n=== FLAG ===")
flag_str = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in flag_bytes)
print(f"Raw bytes: {bytes(flag_bytes).hex()}")
print(f"As string: {flag_str}")
# Also try stripping nulls and showing printable portion
flag_printable = bytes(flag_bytes).split(b'\x00')[0]
print(f"Printable: {flag_printable.decode('ascii', errors='replace')}")
print(f"Flag length: {len(flag_printable)} bytes")
