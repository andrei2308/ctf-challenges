import random, hashlib, string
from Crypto.Cipher import AES

def kdf(pass1, pass2):
    return hashlib.sha256(pass1 + pass2).digest()

def generate_password(length):
    alphabet = string.ascii_lowercase + string.digits + '!'
    return ''.join(random.choice(alphabet) for _ in range(length))

def encrypt(pass1, pass2, plaintext):
    key = kdf(pass1, pass2)
    cipher = AES.new(key, AES.MODE_CTR, nonce=pass2)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

FLAG = open("flag.txt").read().strip()

print("=== Task Force Phoenix - Operation Blackout Interface ===")
print("Welcome, agent. Secure communications are now active.")
print("----------------------------------------------------------")

server_secret = generate_password(8)
while True:
    try:
        pass2 = input("Enter your secure access key: ")
        user = input("Enter your Agent Codename: ")
        assert len(pass2) == 8, "Secure access key must be 8 characters long."
        assert len(user) < 1337, "Codename too long."

        print("Establishing secure communication channel...")

        shared_secret = f"Agent {user}, your clearance for Operation Blackout is: {FLAG}. It is mandatory that you keep this information confidential."
        ciphertext = encrypt(server_secret.encode(), pass2.encode(), shared_secret.encode())

        print(f"Encrypted transmission: {ciphertext.hex()}")
        print("--- End of Transmission ---")
    except Exception as e:
        print(e)
        print("Transmission error.")