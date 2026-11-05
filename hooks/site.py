"""MkDocs build hook for the blog's structure. Everything here is automatic:
drop a new writeup folder into an event and it shows up in the nav and the
counts on the next build.

- on_config: expands the `CTFs` nav entry into one section per event, each
  listing its writeups (grouped by category folder where the event has them).
- placeholders filled in page markdown:
    <!-- CTF_EVENTS -->     events table on ctfs/index.md
    <!-- EVENT_META -->     count + tracks line on each event's index.md
    <!-- CTF_COUNT -->      total CTF writeups (home page)
    <!-- EVENT_COUNT -->    number of events/platforms (home page)
"""

import os

from mkdocs.utils import get_relative_url

# folder, display name, year (None = training platform), tracks
EVENTS = [
    ("unbreakable2026", "Unbreakable", 2026, "Reversing, web, threat hunting, pwn"),
    ("rocsc2026", "ROCSC", 2026, "Web, pwn, OSINT, mobile, AI"),
    ("HackTheBox-University2025", "HTB University CTF", 2025, "Pwn, reversing, web, forensics"),
    ("rocsc2025", "ROCSC", 2025, "Math, web, OSINT"),
    ("ismctf2025", "ISM CTF", 2025, "Reversing"),
    ("HackTheBox", "Hack The Box", None, "Crypto, reversing, web, pwn, blockchain"),
    ("cyberedu", "CyberEDU", None, "Pwn, crypto, forensics, web, stego"),
    ("pwnable.kr", "pwnable.kr", None, "Binary exploitation, beginner to advanced"),
]

CATEGORY_LABELS = {
    "blockchain": "Blockchain",
    "crypto": "Crypto",
    "cryptography": "Crypto",
    "forensics": "Forensics",
    "misc": "Misc",
    "pwn": "Pwn",
    "rev_engineering": "Reversing",
    "reverse_engineering": "Reversing",
    "reversing": "Reversing",
    "steganography": "Stego",
    "web": "Web",
}

# event folder -> [(category or None, challenge name, src path)]
_EVENTS = {}


def _label(name, year):
    return "%s %s" % (name, year) if year else name


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _scan(docs_dir, folder):
    base = os.path.join(docs_dir, folder)
    out = []
    for root, dirs, files in os.walk(base):
        dirs.sort(key=str.lower)
        for fn in sorted(files, key=str.lower):
            if not fn.endswith(".md"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), docs_dir).replace(os.sep, "/")
            if rel == folder + "/index.md":
                continue
            mid = rel.split("/")[1:-1]
            if not mid:
                cat, name = None, os.path.splitext(fn)[0]
            elif len(mid) == 1:
                cat, name = None, mid[0]
            else:
                cat, name = mid[0], mid[-1]
            out.append((cat, name, rel))
    out.sort(key=lambda e: (CATEGORY_LABELS.get(e[0], e[0] or ""), e[1].lower()))
    return out


# --------------------------------------------------------------------- nav --
def _event_nav(folder, entries):
    children = [folder + "/index.md"]
    if any(cat for cat, _, _ in entries):
        groups = {}
        for cat, name, rel in entries:
            groups.setdefault(CATEGORY_LABELS.get(cat, cat or "Other"), []).append({name: rel})
        children += [{label: items} for label, items in groups.items()]
    else:
        children += [{name: rel} for _, name, rel in entries]
    return children


def on_config(config):
    docs_dir = config["docs_dir"]
    _EVENTS.clear()
    for folder, _, _, _ in EVENTS:
        if os.path.isfile(os.path.join(docs_dir, folder, "index.md")):
            _EVENTS[folder] = _scan(docs_dir, folder)

    nav = config.get("nav") or []
    for i, item in enumerate(nav):
        if isinstance(item, dict) and "CTFs" in item and isinstance(item["CTFs"], str):
            section = [item["CTFs"]]
            for folder, name, year, _ in EVENTS:
                if folder in _EVENTS:
                    section.append({_label(name, year): _event_nav(folder, _EVENTS[folder])})
            nav[i] = {"CTFs": section}
    return config


# ------------------------------------------------------------- placeholders --
def _url(files, src, page):
    f = files.get_file_from_path(src)
    return get_relative_url(f.url, page.file.url) if f else "#"


def _count_label(n):
    return "%d writeup%s" % (n, "" if n == 1 else "s")


def _events_table(files, page):
    groups = [
        ("Competitions", [e for e in EVENTS if e[2] and e[0] in _EVENTS], "year"),
        ("Training platforms", [e for e in EVENTS if not e[2] and e[0] in _EVENTS], ""),
    ]
    out = []
    for title, events, year_head in groups:
        if not events:
            continue
        rows = [
            '<li class="rows__headrow"><div class="rows__head"><span>%s</span><span>name</span>'
            '<span class="row__tracks">tracks</span><span class="row__meta--end">writeups</span></div></li>'
            % year_head
        ]
        for folder, name, year, tracks in events:
            rows.append(
                '<li><a href="%s"><span class="row__meta">%s</span><span class="row__name">%s</span>'
                '<span class="row__tracks">%s</span><span class="row__count">%d</span></a></li>'
                % (_url(files, folder + "/index.md", page), year or "", _esc(name),
                   _esc(tracks), len(_EVENTS[folder]))
            )
        out.append("## %s\n\n<ul class=\"rows rows--events\">\n%s\n</ul>\n" % (title, "\n".join(rows)))
    return "\n".join(out)


def _event_meta(folder):
    for d, _, year, tracks in EVENTS:
        if d == folder:
            return ('<p class="event-meta"><span><b>%d</b> %s</span><span>%s</span></p>'
                    % (len(_EVENTS[folder]), "writeup" if len(_EVENTS[folder]) == 1 else "writeups",
                       _esc(tracks)))
    return ""


# ------------------------------------------------------------------- hook --
def on_page_markdown(markdown, page, config, files):
    if "<!--" not in markdown:
        return markdown

    if "<!-- CTF_EVENTS -->" in markdown:
        markdown = markdown.replace("<!-- CTF_EVENTS -->", _events_table(files, page))

    if "<!-- EVENT_META -->" in markdown:
        folder = page.file.src_uri.split("/")[0]
        markdown = markdown.replace("<!-- EVENT_META -->", _event_meta(folder) if folder in _EVENTS else "")

    if "<!-- CTF_COUNT -->" in markdown:
        markdown = markdown.replace("<!-- CTF_COUNT -->", str(sum(len(v) for v in _EVENTS.values())))

    if "<!-- EVENT_COUNT -->" in markdown:
        markdown = markdown.replace("<!-- EVENT_COUNT -->", str(len(_EVENTS)))

    return markdown
