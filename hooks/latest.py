"""MkDocs build hook: inject a "latest writeups" list into the home page.

Replaces the `<!-- LATEST_WRITEUPS -->` placeholder in docs/index.md with a
compact list of the most recently updated writeups, ranked by git commit date
(falling back to file mtime when git history isn't available, e.g. a shallow
clone). Fully automatic — new writeups surface here as soon as they're committed.
"""

import os
import re
import subprocess
import time

from mkdocs.utils import get_relative_url

PLACEHOLDER = "<!-- LATEST_WRITEUPS -->"
MAX_ITEMS = 6

PLATFORMS = {
    "vulnerability-research": "Vuln Research",
    "rocsc2026": "ROCSC 2026",
    "rocsc2025": "ROCSC 2025",
    "unbreakable2026": "Unbreakable 2026",
    "HackTheBox": "Hack The Box",
    "HackTheBox-University2025": "HTB University 2025",
    "cyberedu": "CyberEDU",
    "pwnable.kr": "pwnable.kr",
    "ismctf2025": "ISM CTF 2025",
}

_FENCE = re.compile(r"^\s*(```|~~~)")
_H1 = re.compile(r"^#\s+(.+?)\s*(\{.*\})?\s*$")
_H1_HTML = re.compile(r"<h1[^>]*>(.*?)</h1>", re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")

_cache = {"html": None}


def _repo_root(config):
    cfg = config.get("config_file_path")
    return os.path.dirname(os.path.abspath(cfg)) if cfg else os.getcwd()


def _git_timestamp(root, abs_path):
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%ct", "--", abs_path],
            cwd=root, capture_output=True, text=True, timeout=10,
        )
        s = out.stdout.strip()
        if s:
            return int(s)
    except Exception:
        pass
    try:
        return int(os.path.getmtime(abs_path))
    except OSError:
        return 0


def _title(abs_path):
    try:
        with open(abs_path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    in_fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _H1.match(line.strip())
        if m:
            title = m.group(1).strip()
            if title and "<" not in title and "sr-only" not in (m.group(2) or ""):
                return title
    m = _H1_HTML.search(text)
    if m:
        t = _TAGS.sub("", m.group(1)).strip()
        if t and "Security Research" not in t:
            return t
    return None


def _humanize(name):
    return re.sub(r"[-_]+", " ", name).strip()


def _challenge_and_platform(src_uri):
    parts = src_uri.split("/")
    platform = PLATFORMS.get(parts[0], _humanize(parts[0]))
    name = None
    for d in reversed(parts[:-1]):
        if d.lower() in ("writeup", "writeups"):
            continue
        name = d
        break
    if not name:
        name = os.path.splitext(parts[-1])[0]
    return name, platform


def _relative_age(ts):
    if ts <= 0:
        return ""
    days = int((time.time() - ts) // 86400)
    if days <= 0:
        return "today"
    if days == 1:
        return "1d ago"
    if days < 14:
        return "%dd ago" % days
    if days < 60:
        return "%dw ago" % (days // 7)
    if days < 365:
        return "%dmo ago" % (days // 30)
    return "%dy ago" % (days // 365)


def _is_writeup(src_uri):
    if not src_uri.endswith(".md"):
        return False
    if os.path.basename(src_uri) == "index.md":
        return False
    if src_uri == "repository.md":
        return False
    return True


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build(config, files, page):
    root = _repo_root(config)
    ranked = []
    for f in files.documentation_pages():
        if not _is_writeup(f.src_uri):
            continue
        ranked.append((_git_timestamp(root, f.abs_src_path), f))
    ranked.sort(key=lambda x: x[0], reverse=True)

    rows = []
    for ts, f in ranked[:MAX_ITEMS]:
        name, platform = _challenge_and_platform(f.src_uri)
        label = _title(f.abs_src_path) or _humanize(name)
        age = _relative_age(ts)
        meta = platform + (" · " + age if age else "")
        url = get_relative_url(f.url, page.file.url)
        rows.append(
            '<li><a href="%s"><span class="recent__name">%s</span>'
            '<span class="recent__meta">%s</span></a></li>'
            % (url, _esc(label), _esc(meta))
        )
    if not rows:
        return ""
    return '<ul class="recent">\n' + "\n".join(rows) + "\n</ul>"


def on_page_markdown(markdown, page, config, files):
    if PLACEHOLDER not in markdown:
        return markdown
    if _cache["html"] is None:
        _cache["html"] = _build(config, files, page)
    return markdown.replace(PLACEHOLDER, _cache["html"] or "")
