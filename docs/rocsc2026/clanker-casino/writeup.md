# Clanker Casino — CTF Writeup

**Category:** Web / Misc  
**Flag:** `CTF{954eab9fa51e0aeecd2bab944f60ee15af0a064d97651719752865208c28bc24}`

## Description

> People tried to cheat the system with computers. Now it is time to cheat computers with human input.

## Overview

The challenge is a Flask-based coin-flip gambling app. Players register with 1 coin and must reach **200 coins** to see the flag. Each bet is a fair 50/50 coin flip — heads pays 2×, tails loses the bet. Every flip requires solving a CAPTCHA before submission.

The twist: the CAPTCHA uses a **custom font with OpenType contextual alternates** that visually scrambles the digits. The HTML source says one thing, but the browser renders something different. A human reading the screen sees different numbers than a bot reading the HTML.

## Source Code Analysis

### `app.py`

- Users start with 1 coin, flag is shown at ≥200 coins.
- The coin flip uses `secrets.choice(['heads', 'tails'])` — truly random, no way to predict.
- Each round generates a CAPTCHA via `generateCaptcha()`, stores the solution server-side keyed by a random token in the session.
- The CAPTCHA answer must match exactly to proceed.

### `captcha.py`

The local stub is a placeholder (`return {"html_source": "00+00", "solution": 78}`). The real implementation on the remote generates expressions like `AB+CD` where A, B, C, D are digits 0–9.

### Key CSS (`style.css`)

```css
.captcha-container {
    font-family: 'editundo', sans-serif;
    font-size: 40px;
    font-feature-settings: "calt" 1;
    user-select: none;
}
```

The `font-feature-settings: "calt" 1` enables **Contextual Alternates** — an OpenType feature that substitutes glyphs based on surrounding characters. The `user-select: none` prevents copy-paste.

### `editundo.ttf`

The font is served from `/font/editundo.ttf`. It contains a `GSUB` table with a `calt` feature (Lookup 0, type 6 — Chaining Contextual Substitution) that references 19 single-substitution lookups. The rules swap digit glyphs based on:

- What digit follows (lookahead context)
- What digit precedes (backtrack context)
- Whether the `+` sign is adjacent

For example, when rendering `17+43`:
- The `1` sees `7` ahead and `+` two positions ahead → gets substituted
- The `7` sees backtrack context of the substituted `1` and lookahead `+` → gets substituted
- After `+`, the `4` and `3` are similarly remapped

The result is that `17+43` in HTML might render visually as `45+15` on screen.

## Solution

### Step 1: Download and Analyze the Font

```python
import requests
r = requests.get('http://TARGET/font/editundo.ttf')
with open('editundo.ttf', 'wb') as f:
    f.write(r.content)
```

Using `fontTools`, we confirmed the font has a complex `calt` GSUB feature with 20 lookups implementing contextual digit substitution.

### Step 2: Build a Visual Mapping Table

Since Pillow on this system has HarfBuzz support (`features.check('harfbuzz') == True`), we can render text with OpenType features applied:

```python
from PIL import Image, ImageDraw, ImageFont

font = ImageFont.truetype('editundo.ttf', 60)

# Render with calt enabled (default in HarfBuzz)
img = Image.new('L', (300, 80), 255)
draw = ImageDraw.Draw(img)
draw.text((10, 5), "17+43", font=font, fill=0)

# Render without calt for comparison
img_raw = Image.new('L', (300, 80), 255)
draw = ImageDraw.Draw(img_raw)
draw.text((10, 5), "17+43", font=font, fill=0, features=['-calt'])
```

We confirmed these produce different images — `calt` is actively remapping digits.

To build the complete mapping, we:

1. Rendered each isolated digit 0–9 as a reference (no contextual substitution applies to single characters).
2. Rendered all 100 possible two-digit left-side values (`00`–`99`) in context `AB+00` with `calt`, then compared each rendered digit against the references to identify the visual digit.
3. Did the same for the right side: `00+CD` for all `CD` values.
4. Combined the mappings: for source expression `AB+CD`, the visual sum = `visual(AB) + visual(CD)`.

This produced a lookup table of 10,000 entries mapping every possible `AB+CD` to its correct visual answer.

### Step 3: Automate the Game

The gambling strategy is simple: **always go all-in**. Starting from 1 coin, we need 8 consecutive heads to reach 256 (≥200). The probability is $(1/2)^8 = 1/256$ per attempt. On failure, we re-register a new account and try again.

```python
while coins < 200 and coins > 0:
    captcha, coins, page = get_captcha_and_coins(session)
    answer = solutions[captcha]       # lookup visual sum
    coins, flashes, flag = play_round(session, coins, answer)
    if flag:
        print(flag)
        break
if coins == 0:
    # re-register and try again
```

After ~282 attempts (≈1 minute of automated play), we hit a streak of 8 consecutive wins and the flag was displayed.

## Key Insight

The challenge title hints at it: *"cheat computers with human input."* A human looking at the browser sees the correct (visually rendered) digits thanks to the font's contextual alternates. A bot reading the HTML source sees the raw (unsubstituted) digits. The CAPTCHA solution is computed from the **visual** representation, not the source — so you need to reverse-engineer the font's glyph substitution to solve it programmatically.
