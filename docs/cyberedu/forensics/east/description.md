
## Challenge: East
**Type:** Forensics

### Step 1: Initial Analysis
We're given a `.jpg` file that appears to be a normal image, but in forensics challenges, files often contain hidden data.

### Step 2: Discovery with Binwalk
```bash
binwalk camashadefortza.jpg
```
Binwalk reveals a 7-Zip archive embedded at offset 206006 (0x324B6).

### Step 3: Extract the Hidden Archive
```bash
dd if=camashadefortza.jpg of=extracted_archive.7z bs=1 skip=206006
```
This extracts the 7z archive starting from the discovered offset.

### Step 4: Password Cracking
The extracted 7z archive is password protected. Using a custom bash brute forcer:

```bash
#!/bin/bash
# Simple 7z password brute forcer
while IFS= read -r password; do
    [[ -z "$password" ]] && continue
    echo -ne "\rTrying: $password                    "
    if 7z t -p"$password" extracted_archive.7z >/dev/null 2>&1; then
        echo -e "\nSUCCESS: Password found: '$password'"
        7z x -p"$password" extracted_archive.7z
        break
    fi
done < <your path to rockyou.txt>
```

### Step 5: Extract and Analyze
After finding the correct password, we extract the archive and find a file called `beaches.001`.

### Step 6: Flag Discovery
```bash
strings beaches.001 | grep ctf
```
This command searches for readable strings containing "ctf" in the extracted file, revealing the flag.

### Tools Used:
- `binwalk` - For discovering embedded files
- `dd` - For manual file extraction
- Custom bash script - For password brute forcing
- `strings` - For extracting readable text from binary files

### Key Learning Points:
1. **Steganography in images** - Data can be hidden inside image files
2. **Offset-based extraction** - Using `dd` with specific byte offsets
3. **Password brute forcing** - Systematic testing of common passwords
4. **String analysis** - Extracting meaningful data from binary files

This is a classic forensics challenge combining steganography, archive analysis, and string extraction techniques!