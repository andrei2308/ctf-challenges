def xor_bytes(b1, b2):
    return bytes(a ^ b2[i % len(b2)] for i, a in enumerate(b1))

# 1. Read the first 64 bytes of your known plaintext and ciphertext
with open('file', 'rb') as f1, open('file.enc', 'rb') as f2:
    plain_bytes = f1.read(64)
    cipher_bytes = f2.read(64)

# 2. Extract the key (Plaintext XOR Ciphertext = Key)
extracted_key = xor_bytes(plain_bytes, cipher_bytes)
print(f"Extracted Key (Hex): {extracted_key.hex()}")

# 3. Test the key on secret.enc
with open('secret.enc', 'rb') as f_sec:
    secret_encrypted = f_sec.read(1000)

test_decryption = xor_bytes(secret_encrypted, extracted_key)
print(f"Decrypted secret.enc header: {test_decryption}")