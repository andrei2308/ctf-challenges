# in_search — Writeup

## Challenge Description

A backup from a secure Android notes application was recovered. The database does not display the secret note, but the WAL (Write-Ahead Log) contains it. The task is to reverse engineer the key derivation, decrypt the payloads, and recover the flag from the WAL.

**Files provided:** `app.apk`, `case.zip`

## Solution

### 1. Examine the backup (`case.zip`)

Extracting the zip reveals:
- `databases/notes.db` — empty SQLite database (0 rows)
- `databases/notes.db-wal` — WAL file containing all data
- `databases/notes.db-shm` — shared memory file
- `shared_prefs/security.xml` — PBKDF2 parameters

From `security.xml`:
```xml
<int name="pin_length" value="8" />
<int name="pbkdf2_iter" value="150000" />
<int name="dk_len" value="32" />
<string name="salt_b64">8uOT9OHUHNLoqjpOelb2Gw==</string>
<boolean name="digits_only" value="true" />
```

### 2. Decompile the APK

Using androguard, the key classes are found under `com.rocsc.securenotes`:

- **`Security`** — Key derivation and encryption
  - `deriveKey(pin, params)`: PBKDF2-HMAC-SHA256 with password = `{PIN}:{pepper}`
  - `encryptAesGcm(key, nonce, plaintext)`: AES-256-GCM with 128-bit tag
  - `nonceFromTs(ts)`: SHA256(`"no"` + `ts_le_16bytes`)[:12]

- **`Native`** — JNI library providing the pepper string
- **`Payload`** — MessagePack serialization: `{v: 2, type: 2, ts: <timestamp>, body: <text>}`
- **`CrashInsertActivity`** — Inserts 12 dummy notes (committed), then inserts the flag note and immediately kills the process (uncommitted, stays in WAL)

### 3. Extract the pepper from `libnative.so`

The native `pepper()` function loads 23 bytes from `.rodata` at offset `0x13020` and XORs each byte with `0x5A`:

```python
raw = so_data[0x13020:0x13020 + 23]
pepper = bytes(b ^ 0x5A for b in raw)  # "v2::rocsc::pepper::9f3a"
```

### 4. Find the uncommitted flag entry in the WAL

The WAL has 245 frames. The last frame (frame 245) is uncommitted (`commit_size=0`) and contains a cell with `rowid=121` and `payload_len=127` — much larger than the 61-byte dummy entries. This is the flag note that was written to the WAL but never committed (process was killed before `setTransactionSuccessful()`).

Parsing the SQLite record from this frame:
- **Timestamp:** `1770718678059`
- **Ciphertext (116 bytes):** `8605627d8eeced...`

### 5. Brute-force the PIN and decrypt

The PIN is 8 digits. Testing common PINs, **`12345678`** succeeds:

```
Key derivation: PBKDF2-HMAC-SHA256("12345678:v2::rocsc::pepper::9f3a", salt, 150000, 32)
Nonce: SHA256("no" + LE_bytes(1770718678059, 16))[:12]
Decryption: AES-256-GCM(key, nonce, ciphertext)
```

Decrypted MessagePack payload:
```json
{"v": 2, "type": 2, "ts": 1770718678059, "body": "ROCSC{6d462872c4d475ff466967aa33d6dabc1a5052aea279cda9f5600656ca4bd26f}"}
```

## Flag

```
ROCSC{6d462872c4d475ff466967aa33d6dabc1a5052aea279cda9f5600656ca4bd26f}
```
