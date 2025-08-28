# Hidden Handshake - CTF Write-up

## Challenge Information
**Title:** Hidden Handshake

**Description:** Amidst the static hum of Volnaya's encrypted comms, Task Force Phoenix detects a subtle, silent handshake—a fleeting, ghostly link hidden beneath layers of noise. Your objective: capture, decode, and neutralize this quiet whisper before it escalates into a deafening roar that plunges nations into chaos.

## Analysis

Looking at the `server.py` file, we can identify this as a cryptography challenge where we need to decrypt a message to obtain the flag.

Analyzing the code reveals the following key points:

- The program takes `pass2` as input from the user and uses it in the encryption scheme
- The program takes `username` as input from the user and includes it in the final message  
- The program returns an encrypted message containing the flag and username
- **The encryption scheme used is AES in Counter (CTR) mode**

## Vulnerability: Nonce Reuse

The critical vulnerability lies in how AES CTR mode is implemented:

- AES CTR mode uses `pass2` as the nonce
- If we send two inputs with the same `pass2`, we get two encrypted messages using the **same nonce**
- **Nonce reuse in CTR mode is a critical vulnerability**

### How AES CTR Mode Works

AES CTR mode encrypts data by:
1. Generating a keystream based on the nonce
2. XORing the keystream with plaintext blocks
3. **Same nonce = Same keystream**

## Attack Strategy

Our attack leverages the nonce reuse vulnerability:

1. **Send two requests with identical `pass2` values** (same nonce)
2. **First request:** Use a very long username to recover more keystream
3. **Second request:** Use a short username to decrypt more of the message

### Keystream Recovery

Since: `Ciphertext = Plaintext ⊕ Keystream`

We can recover the keystream: `Keystream = Plaintext ⊕ Ciphertext`

With a long known plaintext, we recover a large portion of the keystream, which we can then use to decrypt the shorter message containing the flag.

## Exploitation

### Inputs Sent to Server:
- **Request 1:** `pass2 = "constant"`, `username = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
- **Request 2:** `pass2 = "constant"`, `username = "a"`

### Exploit Code:

```python
from pwn import xor

# Known plaintext and corresponding ciphertext from first request (long username)
plain_text_1 = b"Agent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, your clearance for Operation Blackout is: "
cypher_text_1 = bytes.fromhex("eabaf4a21006a44e95cb3d0a4fa71af5ad6cb409dc3a3002d42365b96d05e8cba5857ecd2a037749ae3e912d1fb32ebf0845d448393640e3db5496254e0e25023763b45c8191b6e4bcd1b62f03925b31be8804d4b5b393546256cbf69cb95c79963f54f76bb3e569eae510de60f31918538625ed21c5b0dd87347d85471c88bd1cb0783e15cda3a37ba96867a32ffe951357d3e2dc409facb82bf1ba9d545c7ca95b4b1c124f202c234e86e3582638a26d45a40f2b338275fced9d090b060c8f43dce778f16d14901e20a4a794838a5804ad1009135b1add96773ad1ceb125d5525bb40e5fa2a6de05c48e376353f6b460690a307cab0de48fd6241132d6ac9ebdf55abaf7587200131ea2162e6abaf8f1470632eab1622c")

# Plaintext and ciphertext from second request (short username)  
plain_text_2 = b"Agent a, your clearance for Operation Blackout is: "
cypher_text_2 = bytes.fromhex("eabaf4a21006a403d4d3331e5ce618f8a96ca709d3383443d32d76f84314ecd8a59076c325425444ae3c9b230ba66fb71a1e95610c155af489478e1b415e2750775d8a62d4afb5b4a9efa43e5390430fb4da1cc6a0a0c1016e68d8a488ab0e65d97e7ce22abbf728e6e51fdb60e6170b4bc730e421d0f1c589203c8f431899fc09f431345ad1bfe577b76067a527ff985614dae3c809b4b9b32df9af9815")

# Recover keystream by XORing known plaintext with its ciphertext
keystream = xor(plain_text_1, cypher_text_1)
print("Keystream:", keystream)

# Use recovered keystream to decrypt the second message
decrypted_message = xor(cypher_text_2, keystream)
print("Decrypted message:", decrypted_message.decode('utf-8'))
```

## Key Takeaways

- **Never reuse nonces in CTR mode** - this breaks the security completely
- **Known plaintext attacks** become trivial when keystreams are reused  
- **AES CTR mode** requires unique nonces for each encryption operation
- **Stream cipher reuse** is a fundamental cryptographic vulnerability

The flag is revealed in the decrypted message from the second request.