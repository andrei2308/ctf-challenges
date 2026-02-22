# Art Gallery Heist — OSINT Writeup

**Category:** OSINT  
**Flag:** `ROCSC{n0_ch@in_c@n_ev3r_h0ld_me_d0wn}`

## Overview

We are given an image and must use OSINT techniques to trace it back to its origin, find the owner, and ultimately discover the flag hidden on their social media.

## Solution

### Step 1 — Reverse Image Search

Using Google reverse image search on the provided challenge image, we find a match leading to the website [https://toshthecreator.com/websites/](https://toshthecreator.com/websites/). From this site, we identify the name of the NFT collection: **Ocean Racing Leagues**.

### Step 2 — Find the NFT on OpenSea

Navigating to OpenSea and searching for the "Ocean Racing Leagues" collection, we apply the following trait filters to narrow down the specific NFT from the challenge image:

- **Background:** intergalactic
- **Phantskin:** camo

This leads us to the exact NFT, owned by wallet address:

```
0xe31f336e1a6983c1a77e1ff7edeaaac1e5d088d3
```

### Step 3 — Trace the Wallet Owner

Searching for the wallet address `0xe31f336e1a6983c1a77e1ff7edeaaac1e5d088d3` on Google reveals the associated GitHub account:

[https://github.com/unchainedmf](https://github.com/unchainedmf)

The GitHub profile bio reads: **"Send me memes on Twitter"** — pointing us to their Twitter/X account.

### Step 4 — Find the Flag on Twitter

Searching for the username `unchainedmf` on Twitter (X), we find the account. The flag is posted in one of their tweets, encoded in **Base64**. Decoding it gives us the flag.

## Flag

```
ROCSC{n0_ch@in_c@n_ev3r_h0ld_me_d0wn}
```
