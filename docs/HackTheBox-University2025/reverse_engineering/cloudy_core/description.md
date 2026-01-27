
---

# CloudyCore

> **Description:** Twillie, the memory-minder, was rewinding one of her snowglobes when she overheard a villainous whisper. The scoundrel was boasting about hiding the Starshard's true memory inside this tiny memory core (.tflite). He was so overconfident, laughing that no one would ever think to reverse-engineer a 'boring' ML file. He said he 'left a little challenge for anyone who did,' scrambling the final piece with a simple XOR just for fun. Find the key, reverse the laughably simple XOR, and restore the memory.

## Analysis

In this challenge, we are provided with a `.tflite` file, which is a standard format for TensorFlow Lite machine learning models. The description hints at two critical pieces of information:

1. The flag is hidden inside the model.
2. The final piece is scrambled with a simple **XOR**.

### 1. Extracting Model Tensors

First, I wrote a script to analyze the model and extract the payload and constants using the `tensorflow` library. The script (`extract.py`) is included in this directory.

Running the script produced the following output:

The output reveals three specific tensors:

* **Payload Raw:** `909fe613`
* **Meta Raw:** `f09fe613df70000010a0e613df700000`
* **Const Raw:** `13af8a291a990fef5a1b3488e7444f0959bd76134500570b5d7dd0246b5e5b29e3000000`

The **Const Raw** value is the most interesting; its length and structure suggest it might be the encrypted flag.

### 2. Finding the Key

According to the description, we need a key to XOR this data. I analyzed the binary structure of the `.tflite` file directly using `xxd` to look for string artifacts or hidden keys.

I found a suspicious sequence near offset `0x210`:

```hexdump
00000210: 1000 0000 6b00 4000 3300 4000 7900 4000  ....k.@.3.@.y.@.
00000220: 2100 4000 0000 0600 0800 0400 0600 0000  !.@.............
00000230: 0400 0000 2400 0000 13af 8a29 1a99 0fef  ....$......)....

```

If we filter out the null bytes and the `@` symbols from the ASCII representation, the string **`k3y!`** clearly stands out. This is our XOR key.

### 3. Decryption

With the encrypted bytes and the key, I moved to **CyberChef** to solve the challenge.

1. **From Hex:** Input the `Const Raw` data.
2. **XOR:** Apply the key `k3y!`.
* **Result:** `78 9c f3 42 29 e0 64 dc 23 70 07 f1 8c 77 36 62 6a c4 1d 20 3c 6b 64 72 36 4e a9 4f 58 27 30 1a 9a 6b 33 79`



The resulting bytes start with `78 9c`. This is the standard magic number for a **zlib** compressed stream.

3. **Zlib Inflate:** Decompressing the data reveals the final flag.

---