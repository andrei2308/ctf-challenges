# TheFlagIsALie — CTF Writeup

## Summary

The challenge provided a Unity IL2CPP Linux game build containing an encrypted replay log file (`.unrl` format, ~22 MB). I started by extracting the game assets with UnityPy and enumerating MonoScripts, which revealed an obfuscated `LogRecorder` class (`_o9b4256010e`) and a `FlagObfuscationController`. Inspecting the LogRecorder's MonoBehaviour raw data, I found 16 sequential `int32` values representing an AES-128 key. The `.unrl` file turned out to be ~308,000 individually AES-128-CBC encrypted records, each with a unique IV, containing entity type, ID, timestamp, position, and rotation. I decrypted all records, kept only the last-known position per entity, filtered out "dead" entities (Y < -10, i.e. those that fell off the map), and plotted the remaining 11,907 alive entities' Y vs Z coordinates. The scatter plot visually spells out the flag text.

**Tools used:** Python 3, UnityPy, PyCryptodome, matplotlib, numpy

**Install dependencies:**

```bash
pip install UnityPy pycryptodome matplotlib numpy
```

---

## Step-by-Step Solution

### Step 1: Extract the Game Build

The challenge ships a single file: `TheFlagIsALie_LinuxBuild.zip`. Extracting it reveals a standard Unity IL2CPP Linux build.

**Command:**

```bash
mkdir -p extracted
cd extracted
unzip ../TheFlagIsALie_LinuxBuild.zip
cd ..
```

**Resulting structure:**

```
extracted/
├── TheFlagIsALie.x86_64          # Main executable
├── UnityPlayer.so                # Unity runtime (40 MB)
├── GameAssembly.so               # IL2CPP compiled game code (81 MB)
└── TheFlagIsALie_Data/
    ├── il2cpp_data/Metadata/global-metadata.dat   # IL2CPP v39 metadata
    ├── Logs/
    │   └── session-20260225-111621.unrl           # Encrypted replay log (22 MB)
    ├── level0, level1, level2, ...                # Scene assets
    └── ...
```

The key file is `session-20260225-111621.unrl` — a 22,177,593-byte custom binary replay file.

### Step 2: Analyze Game Assets with UnityPy

Use UnityPy to enumerate all GameObjects and MonoScripts in the asset bundles.

**Script (`enumerate_assets.py`):**

```python
#!/usr/bin/env python3
import UnityPy

env = UnityPy.load('extracted/TheFlagIsALie_Data')

# List all GameObjects
print("=== GameObjects ===")
for obj in env.objects:
    if obj.type.name == 'GameObject':
        data = obj.read()
        print(f"  {data.m_Name}")

# List all MonoScripts (custom C# classes)
print("\n=== MonoScripts ===")
for obj in env.objects:
    if obj.type.name == 'MonoScript':
        data = obj.read()
        print(f"  pid={obj.path_id}: {data.m_Name}")
```

**Command:**

```bash
python3 enumerate_assets.py
```

**Key findings:**

| Game Object     | Entity ID | Notes                      |
|-----------------|-----------|----------------------------|
| Player          | 1         | Player character           |
| Crate           | 2         | Movable crate              |
| PressurePlate   | 3         | Pressure plate             |
| Door            | 4         | Door                       |
| FlagPlat        | —         | Flag platform at (-83.57, 0, 0) |
| LogRecorder     | —         | Records entity positions   |

**Custom MonoScripts:** `Entity`, `PlayerScript`, `FlagObfuscationController`, `_o9b4256010e` (obfuscated LogRecorder), `LogRecorderUI`, `MovingPlatform`

### Step 3: Reverse-Engineer the UNRL Format

Inspect the binary structure of the `.unrl` file.

**Command:**

```bash
xxd extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl | head -20
```

**Script (`parse_unrl_header.py`):**

```python
#!/usr/bin/env python3
import struct

with open('extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl', 'rb') as f:
    data = f.read()

# Header
magic = data[0:4]  # b'UNRL'
version = data[4]   # 0x02
flag = data[8]      # 0x01
print(f"Magic: {magic}, Version: {version}, Flag: {flag}")
print(f"Total size: {len(data):,} bytes")

# Parse first few records to understand structure
offset = 9
for i in range(5):
    c1_len = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    chunk1 = data[offset:offset+c1_len]
    offset += c1_len
    c2_len = struct.unpack_from('<I', data, offset)[0]
    offset += 4
    chunk2 = data[offset:offset+c2_len]
    offset += c2_len
    print(f"Record {i}: IV_len={c1_len}, CT_len={c2_len}")
    print(f"  IV:  {chunk1.hex()}")
    print(f"  CT:  {chunk2.hex()}")

# Count total records
offset = 9
count = 0
while offset < len(data):
    if offset + 4 > len(data): break
    c1_len = struct.unpack_from('<I', data, offset)[0]; offset += 4 + c1_len
    if offset + 4 > len(data): break
    c2_len = struct.unpack_from('<I', data, offset)[0]; offset += 4 + c2_len
    count += 1
print(f"\nTotal records: {count:,}")
```

**Command:**

```bash
python3 parse_unrl_header.py
```

**Result — UNRL binary format:**

```
Header (9 bytes):
  Bytes 0-3:  Magic "UNRL" (0x554E524C)
  Byte 4:     Version = 0x02
  Bytes 5-7:  Padding (0x000000)
  Byte 8:     Flag = 0x01

Records (72 bytes each, ~308,000 total):
  [4 bytes] uint32 LE = 0x10 (16) — length of chunk1
  [16 bytes] chunk1 — AES IV (unique per record)
  [4 bytes] uint32 LE = 0x30 (48) — length of chunk2
  [48 bytes] chunk2 — AES-128-CBC ciphertext (3 AES blocks)
```

Each record is encrypted independently with its own IV. The near-maximum entropy (~8 bits/byte) confirms encryption rather than simple compression.

### Step 4: Find the AES Key in MonoBehaviour Data

Dump all MonoBehaviour raw data grouped by script to find the encryption key.

**Script (`dump_mbs.py`):**

```python
#!/usr/bin/env python3
"""Dump all MonoBehaviours grouped by script to find encryption key."""
import UnityPy
import struct

env = UnityPy.load('extracted/TheFlagIsALie_Data')

# Collect MonoScript names by path_id
scripts = {}
for obj in env.objects:
    if obj.type.name == 'MonoScript':
        try:
            data = obj.read()
            scripts[obj.path_id] = {
                'name': data.m_Name if hasattr(data, 'm_Name') else str(obj.path_id),
                'path_id': obj.path_id
            }
        except:
            pass

# Collect MonoBehaviours and group by script
mb_by_script = {}
for obj in env.objects:
    if obj.type.name == 'MonoBehaviour':
        try:
            raw = obj.get_raw_data()
            if len(raw) < 28:
                continue
            # MonoBehaviour header: m_GameObject PPtr (12) + m_Enabled (4) + m_Script PPtr (12) = 28 bytes
            script_path_id = struct.unpack_from('<q', raw, 20)[0]
            script_name = scripts.get(script_path_id, {}).get('name', f'Unknown({script_path_id})')
            if script_name not in mb_by_script:
                mb_by_script[script_name] = []
            mb_by_script[script_name].append({
                'path_id': obj.path_id, 'raw': raw, 'size': len(raw)
            })
        except:
            pass

# Print details for game-specific scripts
for name, mbs in sorted(mb_by_script.items()):
    if name in ['_o9b4256010e', 'FlagObfuscationController', 'Entity', 'PlayerScript']:
        print(f"\n{'='*60}")
        print(f"{name}: {len(mbs)} instances")
        for mb in mbs:
            print(f"  pid={mb['path_id']}, size={mb['size']} bytes")
            for off in range(0, len(mb['raw']), 4):
                val = struct.unpack_from('<i', mb['raw'], off)[0]
                print(f"    raw[{off:3d}]: {val:12d}  ({mb['raw'][off:off+4].hex()})")
```

**Command:**

```bash
python3 dump_mbs.py
```

**Key finding:** The obfuscated LogRecorder script (`_o9b4256010e`, path_id=14) contains 16 sequential `int32` values at the tail of its raw data (raw offset 116–179). Each value represents one byte of the AES-128 key:

```
raw[116]:  38   (0x26)      raw[148]: 229  (0xE5)
raw[120]: 193   (0xC1)      raw[152]: 235  (0xEB)
raw[124]: 193   (0xC1)      raw[156]: 247  (0xF7)
raw[128]:  86   (0x56)      raw[160]: 193  (0xC1)
raw[132]: 162   (0xA2)      raw[164]: 200  (0xC8)
raw[136]:  45   (0x2D)      raw[168]: 185  (0xB9)
raw[140]:  49   (0x31)      raw[172]:  75  (0x4B)
raw[144]: 116   (0x74)      raw[176]: 110  (0x6E)
```

**AES-128 key:**

```
Key = 26 C1 C1 56 A2 2D 31 74 E5 EB F7 C1 C8 B9 4B 6E
```

### Step 5: Decrypt the Records

Verify decryption with AES-128-CBC using the discovered key.

**Script (`test_decrypt.py`):**

```python
#!/usr/bin/env python3
import struct
from Crypto.Cipher import AES

UNRL = 'extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl'
KEY = bytes([38,193,193,86,162,45,49,116,229,235,247,193,200,185,75,110])

with open(UNRL, 'rb') as f:
    data = f.read()

# Decrypt first 5 records to verify
offset = 9
for i in range(5):
    c1_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    iv = data[offset:offset+c1_len]; offset += c1_len
    c2_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    ct = data[offset:offset+c2_len]; offset += c2_len

    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ct)
    pad_len = dec[-1]
    valid = 1 <= pad_len <= 16 and all(b == pad_len for b in dec[-pad_len:])
    pt = dec[:-pad_len]
    print(f"Record {i}: pad={pad_len}, valid={valid}, plaintext_len={len(pt)}")
    print(f"  Plaintext hex: {pt.hex()}")
```

**Command:**

```bash
python3 test_decrypt.py
```

**Result:**

- **Algorithm:** AES-128-CBC  
- **Key:** `bytes([38, 193, 193, 86, 162, 45, 49, 116, 229, 235, 247, 193, 200, 185, 75, 110])`
- **IV:** The 16-byte `chunk1` from each record (unique per record)
- **Padding:** PKCS7 (pad_len=7, producing 41 bytes of plaintext from 48 bytes of ciphertext)

Every record produces valid PKCS7 padding (last 7 bytes are all `0x07`).

### Step 6: Parse the Plaintext Record Format

Analyze the decrypted plaintext to identify the field layout.

**Script (`analyze_format.py`):**

```python
#!/usr/bin/env python3
import struct
from Crypto.Cipher import AES

UNRL = 'extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl'
KEY = bytes([38,193,193,86,162,45,49,116,229,235,247,193,200,185,75,110])

with open(UNRL, 'rb') as f:
    data = f.read()

offset = 9
for i in range(10):
    c1_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    iv = data[offset:offset+c1_len]; offset += c1_len
    c2_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    ct = data[offset:offset+c2_len]; offset += c2_len

    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ct)
    pt = dec[:-dec[-1]]

    et = pt[0]
    eid = struct.unpack_from('<I', pt, 1)[0]
    unk = pt[5:9].hex()
    ts = struct.unpack_from('<f', pt, 9)[0]
    px = struct.unpack_from('<f', pt, 13)[0]
    py = struct.unpack_from('<f', pt, 17)[0]
    pz = struct.unpack_from('<f', pt, 21)[0]
    qx = struct.unpack_from('<f', pt, 25)[0]
    qy = struct.unpack_from('<f', pt, 29)[0]
    qz = struct.unpack_from('<f', pt, 33)[0]
    qw = struct.unpack_from('<f', pt, 37)[0]
    print(f"[{i}] type={et} id={eid} unk={unk} t={ts:.3f} "
          f"pos=({px:.2f},{py:.2f},{pz:.2f}) quat=({qx:.3f},{qy:.3f},{qz:.3f},{qw:.3f})")
```

**Command:**

```bash
python3 analyze_format.py
```

**Result — each decrypted record is 41 bytes:**

| Offset | Size | Type     | Field         |
|--------|------|----------|---------------|
| 0      | 1    | byte     | entity_type   |
| 1      | 4    | uint32   | entity_id     |
| 5      | 4    | bytes    | unknown       |
| 9      | 4    | float32  | timestamp     |
| 13     | 4    | float32  | posX          |
| 17     | 4    | float32  | posY          |
| 21     | 4    | float32  | posZ          |
| 25     | 16   | 4×float  | quaternion (x,y,z,w) |

- **entity_type:** `1` = Player/Crate-type, `3` = PressurePlate-type
- **entity_id:** Unique ID per entity instance (range: 0–12109, with 12,110 unique entities)
- **timestamp:** Monotonically increasing float representing game time
- **posX/Y/Z:** World-space position
- **quaternion:** Rotation

### Step 7: Extract Final Positions and Filter Alive Entities

For each unique `(entity_type, entity_id)` pair, keep only the record with the **highest timestamp** (last known position). Filter out dead entities (those that fell off the map with very negative Y).

**Script (`extract_positions.py`):**

```python
#!/usr/bin/env python3
import struct
from Crypto.Cipher import AES
import numpy as np

UNRL = 'extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl'
KEY = bytes([38,193,193,86,162,45,49,116,229,235,247,193,200,185,75,110])

with open(UNRL, 'rb') as f:
    data = f.read()

# Decrypt all records, keeping last position per entity
offset = 9
entity_last_pos = {}

while offset < len(data):
    if offset + 4 > len(data): break
    c1_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    iv = data[offset:offset+c1_len]; offset += c1_len
    if offset + 4 > len(data): break
    c2_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    ct = data[offset:offset+c2_len]; offset += c2_len
    if c2_len < 48: continue

    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ct)
    pad_len = dec[-1]
    if not (1 <= pad_len <= 16 and all(b == pad_len for b in dec[-pad_len:])): continue
    pt = dec[:-pad_len]
    if len(pt) < 25: continue

    et = pt[0]
    eid = struct.unpack_from('<I', pt, 1)[0]
    t = struct.unpack_from('<f', pt, 9)[0]
    py = struct.unpack_from('<f', pt, 17)[0]
    pz = struct.unpack_from('<f', pt, 21)[0]

    key = (et, eid)
    if key not in entity_last_pos or t > entity_last_pos[key][0]:
        entity_last_pos[key] = (t, py, pz)

# Filter alive entities (Y > -10)
keys = list(entity_last_pos.keys())
pys = np.array([entity_last_pos[k][1] for k in keys])
pzs = np.array([entity_last_pos[k][2] for k in keys])
alive = pys > -10

print(f"Unique entities: {len(entity_last_pos):,}")
print(f"Alive: {alive.sum():,}, Dead: {(~alive).sum():,}")
```

**Command:**

```bash
python3 extract_positions.py
```

**Result:**

- **Total unique entities:** 12,110
- **Alive entities:** 11,907 (9,568 type-1 + 2,339 type-3)
- **Dead entities:** 203

### Step 8: Plot Y vs Z to Reveal the Flag

Plot the alive entities' final positions with **Z on the horizontal axis** and **Y on the vertical axis** (with equal aspect ratio).

**Script (`plot_flag.py`):**

```python
#!/usr/bin/env python3
import struct
from Crypto.Cipher import AES
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

UNRL = 'extracted/TheFlagIsALie_Data/Logs/session-20260225-111621.unrl'
KEY = bytes([38,193,193,86,162,45,49,116,229,235,247,193,200,185,75,110])

with open(UNRL, 'rb') as f:
    data = f.read()

# Decrypt all records, keep last position per entity
offset = 9
entity_last_pos = {}
while offset < len(data):
    if offset + 4 > len(data): break
    c1_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    iv = data[offset:offset+c1_len]; offset += c1_len
    if offset + 4 > len(data): break
    c2_len = struct.unpack_from('<I', data, offset)[0]; offset += 4
    ct = data[offset:offset+c2_len]; offset += c2_len
    if c2_len < 48: continue
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ct)
    pad_len = dec[-1]
    if not (1 <= pad_len <= 16 and all(b == pad_len for b in dec[-pad_len:])): continue
    pt = dec[:-pad_len]
    if len(pt) < 25: continue
    et = pt[0]
    eid = struct.unpack_from('<I', pt, 1)[0]
    t = struct.unpack_from('<f', pt, 9)[0]
    py = struct.unpack_from('<f', pt, 17)[0]
    pz = struct.unpack_from('<f', pt, 21)[0]
    key = (et, eid)
    if key not in entity_last_pos or t > entity_last_pos[key][0]:
        entity_last_pos[key] = (t, py, pz)

# Filter alive (Y > -10) and plot
keys = list(entity_last_pos.keys())
pys = np.array([entity_last_pos[k][1] for k in keys])
pzs = np.array([entity_last_pos[k][2] for k in keys])
alive = pys > -10

fig, ax = plt.subplots(figsize=(40, 10))
ax.scatter(pzs[alive], pys[alive], s=3, c='black', alpha=0.7)
ax.set_xlabel('Z', fontsize=14)
ax.set_ylabel('Y', fontsize=14)
ax.set_title(f'Entity Final Positions — Y vs Z ({alive.sum():,} alive entities)', fontsize=16)
ax.set_aspect('equal')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('flag_output.png', dpi=200)
print(f"Saved flag_output.png ({alive.sum():,} alive entities plotted)")
```

**Command:**

```bash
python3 plot_flag.py
```

The flag is visually readable in the resulting `flag_output.png` scatter plot — thousands of entity positions spell out the flag text.

---

## Solver

See `solver_theflagisalie.py` for the complete standalone solver that performs all steps automatically:

```bash
# Place TheFlagIsALie_LinuxBuild.zip in the working directory, then:
python3 solver_theflagisalie.py
# Output: flag_output.png
```
