# Wonderful Strangers — OSINT Writeup

**Category:** OSINT  
**Flag:** `ROCSC{h0w_d0e5_h3_m0v3_l1k3_th1s}`

## Overview

We are given a username — `memepie6767` — and must use OSINT techniques to trace the user's online presence, identify their connections, and find the flag.

## Solution

### Step 1 — Username Enumeration with Sherlock

Using [Sherlock](https://github.com/sherlock-project/sherlock) to search for the username `memepie6767` across hundreds of platforms, we find accounts on several sites:

- **Roblox** — [https://www.roblox.com/user.aspx?username=memepie6767](https://www.roblox.com/user.aspx?username=memepie6767)
- Wikipedia
- YouTube
- Livelib

The Roblox profile is the most relevant lead.

### Step 2 — Investigate Roblox Connections

Checking the Roblox profile's **friends list**, we find a friend named **BoboNashu**. This user's Roblox profile description contains a clue: they mention posting **weekly videos**.

### Step 3 — Find the YouTube Channel

Searching for "BoboNashu" on YouTube, we find their channel which has video uploads. In one of the videos, the **flag is hidden in the audio track**.

## Flag

```
ROCSC{h0w_d0e5_h3_m0v3_l1k3_th1s}
```
