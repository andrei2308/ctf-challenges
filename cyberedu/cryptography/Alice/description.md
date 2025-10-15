# Alice - CTF Writeup

**Challenge Name:** Alice

## Description

To use her e-mail, Alice needs to connect to a mail server. The authentication is unilateral, and works as follows:

1. Alice requests access to the server by sending her username.
2. The server randomly selects 2 values `index1` and `index2` (`1 <= index1 < index2 <= 64`), and challenges Alice with `(index1, index2)`.
3. Alice applies SHA256 to her password, keeps the hex characters placed on the positions `index1` and `index2` unchanged and changes all the other hex characters to a different value. Then, she sends the result to the server.
4. The server receives the response, and checks if the received string equals the SHA256 value stored in the database for Alice's username in exactly two positions: `index1` and `index2`.
5. To decrease the chances to obtain access by luck, the server repeats the procedure and sends several requests to Alice before allowing her to access the e-mail. If Alice replies correctly to all challenges, then she is successfully authenticated; if not, Alice is denied access.

### Example

- **Username:** `Alice`
- **Password:** `ageneralpassword`
- **SHA256(password):** `aad3eda32ce777fa1cb3ca97ac7e1bfdd726053e05e0109b3526a63fed4519b7`
- **index1 = 5** and **index2 = 60**

**Valid reply** (only hex characters on positions 5 and 60 are unchanged):
```
4c77ef3010c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9ddx475bffe
```

**Invalid reply** (hex characters on positions 9 and 57 are also the same):
```
4c77ef3020c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9dde475bffe
```

**Invalid reply** (hex character on position 5 is different):
```
4c77ff3010c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9ddx475bffe
```

## Challenge Scenario

An adversary masquerades as the server, and fools Alice into replying to his challenges. You are not given access to the challenges, but you know that:
- The adversary only queried positions from the **first half of the hash**
- You have all the replies from Alice in `Alice_replies.txt`
- The adversary found the complete hash
- This hash is your flag

## Given Data

We are provided with the following ciphertexts (Alice's replies):

```
f14fd2705fa37ce36ab73472883cf329917c50eb06d2080f863fd6bf712377b1
ad3b393e6426aef4db1a49180797393a3cb6a7516d1b5f69a3d36138d9be121c
73c370746eb072da5deb8ce13febaa16d33dc714c24a8424018a8a16f46cbdcf
05bac2205f124251c03863a608322b5486c2ba8c1fe0fbaccb1942ed838deb30
312f3b3ef4ce5ef837b1c9837ba8f9ba6f6f21f73eff19ea39e105a1604c61fe
983bd1838b16b697c90731e7602c1a1ce44f4c62032a32f2dfaa50f638f14925
7ec14b2e54a24a7150f121468b5dabb47dd3eb0fbb13ea33b8f7dc171d9fc8ed
313f4b83fbbe56da3a34c0e13fa2e55cf5e5592344c4297b122899629e5290d3
98b1c1348423aa782838204775281aff2e5432782539d3832aa2142b0ca92a34
dc2bc85fa5302c51e919bb59d6eb27dc2a0004b9d867b7505e6528435a16a58a
fe0e584025c1816621aa3c745971c9d9c299733e897d51d6f54cb79ac3770f08
7561b7a5a2348c8bed05b7c9f6e4332718188dc8e0919d1e90bdced42be58476
adc3d4612bd6215627a94b58579ba789003a6faa97566c257d56fdc9a2603290
012f795543d1be84f81584c23b3123365187d52d7abe46cd44c073558534fe62
734ac4a39ee5bc9b6d044c19d9e7c386b7a198d6f188ce48ef04ed0e47d8f35b
3563504f92d40f67f1f8c7a4f57437274b2b1690ad0570b11c9b3f80e6cb5ca7
```

## Solution Strategy

There are **16 ciphertexts** - not an odd number at all! Why 16? Because **16 is the number of hex digits**: `0-9` and `A-F`.

After I counted 16 ciphertexts, I knew exactly what the strategy was:

### The Key Insight

The adversary crafted exactly 16 challenges, one for each possible hex digit. For each challenge:
- The adversary queried the same position in the hash
- Alice changed all hex characters except the ones at the quer### **C Exploit**

Here’s the C exploit for the challenge:

```C
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void reverse_obfuscation(unsigned char *data, int length, unsigned int seed)
{
    srand(seed);

    for (int i = 0; i < length; i++)
    {
        int iVar1 = rand();
        int local_3c = rand();
        local_3c = local_3c & 7;

        data[i] = (data[i] >> local_3c) | (data[i] << (8 - local_3c));

        data[i] = data[i] ^ (unsigned char)iVar1;
    }
}

int main()
{
    FILE *f = fopen("flag.enc", "rb");
    if (!f)
    {
        printf("Cannot open file.enc\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    fread(data, 1, file_size, f);
    fclose(f);

    unsigned int seed = *(unsigned int *)data; // automatically gets the first 4 bytes while casting to unsigned int because unsigned int takes 4 bytes
    printf("Seed: %u (0x%08X)\n", seed, seed);

    int flag_length = file_size - 4;
    reverse_obfuscation(data + 4, flag_length, seed);

    printf("Flag: ");
    for (int i = 0; i < flag_length; i++)
    {
        printf("%c", data[4 + i]);
    }
    printf("\n");

    free(data);
    return 0;
}
```

---ied positions
- By analyzing which hex digit appears exactly once (unchanged) or doesn't appear at all, we can determine the original hash character at that position

### Algorithm

1. **For the first half of the hash** (positions queried by the adversary):
   - Analyze each position across all 16 replies
   - Find the hex digit that appears **only once** at that position
   - This is the original character from Alice's password hash

2. **For the second half of the hash** (positions NOT queried):
   - Analyze each position across all 16 replies
   - Find the hex digit that **doesn't appear** at that position
   - This is the original character from Alice's password hash (Alice never changed it, so it never appears in the modified replies)

### Example

For the first position across all 16 ciphertexts:
```
f, a, 7, 0, 3, 9, 7, 3, 9, d, f, 7, a, 0, 7, 3
```

If we count the occurrences and find that `d` appears only once, then `d` is the first character of the original hash.

For a position in the second half (not queried), if we find that the digit `5` never appears across all 16 replies at that position, then `5` is the original character.

## Implementation

By applying this analysis to all 64 positions:
- Positions 1-32 (first half): Extract the character that appears exactly once
- Positions 33-64 (second half): Extract the character that never appears

This reconstructs Alice's password hash, which is the flag.

A full exploit implementation is available in this repository.

### **Python Exploit**

Here’s the python exploit for the challenge:

```python
from collections import Counter

# List of hashes
hashes = [
    "f14fd2705fa37ce36ab73472883cf329917c50eb06d2080f863fd6bf712377b1",
    "ad3b393e6426aef4db1a49180797393a3cb6a7516d1b5f69a3d36138d9be121c",
    "73c370746eb072da5deb8ce13febaa16d33dc714c24a8424018a8a16f46cbdcf",
    "05bac2205f124251c03863a608322b5486c2ba8c1fe0fbaccb1942ed838deb30",
    "312f3b3ef4ce5ef837b1c9837ba8f9ba6f6f21f73eff19ea39e105a1604c61fe",
    "983bd1838b16b697c90731e7602c1a1ce44f4c62032a32f2dfaa50f638f14925",
    "7ec14b2e54a24a7150f121468b5dabb47dd3eb0fbb13ea33b8f7dc171d9fc8ed",
    "313f4b83fbbe56da3a34c0e13fa2e55cf5e5592344c4297b122899629e5290d3",
    "98b1c1348423aa782838204775281aff2e5432782539d3832aa2142b0ca92a34",
    "dc2bc85fa5302c51e919bb59d6eb27dc2a0004b9d867b7505e6528435a16a58a",
    "fe0e584025c1816621aa3c745971c9d9c299733e897d51d6f54cb79ac3770f08",
    "7561b7a5a2348c8bed05b7c9f6e4332718188dc8e0919d1e90bdced42be58476",
    "adc3d4612bd6215627a94b58579ba789003a6faa97566c257d56fdc9a2603290",
    "012f795543d1be84f81584c23b3123365187d52d7abe46cd44c073558534fe62",
    "734ac4a39ee5bc9b6d044c19d9e7c386b7a198d6f188ce48ef04ed0e47d8f35b",
    "3563504f92d40f67f1f8c7a4f57437274b2b1690ad0570b11c9b3f80e6cb5ca7"
]

# Verify all hashes have the same length
hash_length = len(hashes[0])
assert all(len(h) == hash_length for h in hashes), "All hashes must have the same length"

print(f"Analyzing {len(hashes)} hashes of length {hash_length}")
print("=" * 60)

# All possible hexadecimal characters
all_hex_chars = set('0123456789abcdef')

# Analyze each position
unique_chars_by_position = {}

for position in range(hash_length):
    # Extract character at this position from all hashes
    chars_at_position = [h[position] for h in hashes]

    # Count occurrences of each character
    char_counts = Counter(chars_at_position)

    if position < 32:
        # For positions 0-31: Find characters that appear exactly once
        unique_chars = [char for char, count in char_counts.items() if count == 1]
    else:
        # For positions 32+: Find characters that don't appear at all
        chars_present = set(chars_at_position)
        unique_chars = sorted(list(all_hex_chars - chars_present))

    if unique_chars:
        unique_chars_by_position[position] = unique_chars

# Display results
print("\nPositions with unique characters (appearing only once):")
print("-" * 60)

for position in sorted(unique_chars_by_position.keys()):
    unique_chars = unique_chars_by_position[position]
    print(f"Position {position:2d}: {', '.join(unique_chars)}")

# Summary
print("\n" + "=" * 60)
print(f"Total positions analyzed: {hash_length}")
print(f"Positions with unique characters: {len(unique_chars_by_position)}")

# Optional: Build a string from all unique characters in order
if unique_chars_by_position:
    print("\n" + "=" * 60)
    print("Concatenated unique characters (in position order):")
    result = ""
    for position in sorted(unique_chars_by_position.keys()):
        result += "".join(unique_chars_by_position[position])
    print(result)
```

---

## Key Takeaways

- **Frequency Analysis**: The solution relies on analyzing character frequency across multiple samples
- **Protocol Weakness**: The authentication protocol leaks information when an adversary can control the challenges
- **Clever Data Structure**: The adversary used exactly 16 challenges (one per hex digit) to maximize information leakage
- **Two-Phase Analysis**: Different strategies for queried vs non-queried positions
