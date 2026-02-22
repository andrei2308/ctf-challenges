# Echoes of the Past - Writeup

**Category:** Steganography  
**Author:** Joker  
**Flag:** `CTF{2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea}`

## Challenge Description

> You received an audio recording titled past_echoes.wav. It sounds repetitive — almost like something is being repeated back to you. There's a hidden message inside the audio. Once you recover it, follow the instruction… and don't forget to look into the past for the username.

## Solution

### Step 1 — Analyze the WAV File

We start by examining the file metadata:

```bash
ffprobe past_echoes.wav
```

Key findings:
- **Format:** 16-bit PCM, mono, 44100 Hz
- **Duration:** 4 minutes 19 seconds (259.2s)
- **Metadata tag:** `PSTD: Past Date=06.07.2022`

The metadata contains a date — this is the "past" the description hints at.

### Step 2 — Discover the Repeated Structure

The description says the audio "sounds repetitive — almost like something is being repeated back to you." We check if the file is split into two identical (or near-identical) halves:

```python
half = len(samples) // 2  # 5715360 samples = 129.6s each
correlation = np.corrcoef(samples[:half], samples[half:])[0, 1]
# correlation = 0.93 — extremely high
```

The audio is essentially the same content played twice, with subtle differences between the halves.

### Step 3 — Decode the Beep Pattern

The audio consists of 440 Hz beeps separated by gaps of varying lengths. Using RMS energy analysis with 10ms windows, we identify four distinct gap types:

| Gap Duration | Symbol | Meaning |
|---|---|---|
| ~0.02s | C | Connect (beeps form a pair) |
| ~0.62s | S | Short gap within a group |
| ~0.82s | L | Long gap within a group |
| ~1.42s | X | Separator between groups |

Gaps always come in pairs: either `(L, S)` representing binary `1`, or `(C, X)` representing binary `0`.

Each half encodes a 72-bit binary string (9 bytes):

| Half | Bits | ASCII |
|---|---|---|
| First | `011001110110111101110100011011110111001001101111011000110111001101100011` | **gotorocsc** |
| Second | `001011100111001001101111011010010110111001110000011000010111001101110100` | **.roinpast** |

### Step 4 — Follow the Instruction

Combining both halves gives the message: **"go to rocsc.ro in past"**

Together with the WAV metadata `Past Date=06.07.2022`, this tells us to visit `rocsc.ro` on the Wayback Machine around July 6, 2022.

### Step 5 — Find the Username

Visiting [https://web.archive.org/web/20220706114303/https://www.rocsc.ro/](https://web.archive.org/web/20220706114303/https://www.rocsc.ro/) reveals the 2022 version of the site, which was an OSjs-based web desktop.

The login form in `osjs.js` had **pre-filled credentials**:

```js
login: {
  username: 'demo',
  password: 'demo'
}
```

### Step 6 — Compute the Flag

The flag is the SHA256 hash of the username `demo`:

```bash
echo -n "demo" | sha256sum
# 2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea
```

**Flag:** `CTF{2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea}`
