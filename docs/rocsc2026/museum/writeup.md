# Museum — OSINT Writeup

**Category:** OSINT  
**Flag:** `ROCSC{sichuan_science_and_technology_museum}`

## Overview

We are given an image of a building/landmark and must identify the museum it depicts. The flag is the museum's name in a specific format.

## Solution

### Step 1 — Reverse Image Search

Using Google reverse image search on the provided challenge image, we find visually similar images appearing in articles on Chinese websites.

### Step 2 — Translate and Identify

Translating the Chinese article to English (or Romanian), we find the name of the building: the **Sichuan Science and Technology Museum** (四川科技馆), located in Chengdu, Sichuan Province, China.

## Flag

```
ROCSC{sichuan_science_and_technology_museum}
```
