"""Generate the home-page ASCII scene: night rooftops, utility wires across a
big moon, a cat on a roof, one lit window. Prints an HTML <pre> body with
colour spans (classes: m=moon, w=wire, p=pole, b=building, l=lit window,
s=star, c=cat, g=the green window). Colours live in extra.css (.nightscape).

Regenerate: python scripts/ascii_scene.py > scene.html, then paste the output
between <pre aria-hidden="true"> and </pre> in docs/index.md."""
import math
import random

W, H = 160, 30
random.seed(2308)

grid = [[" "] * W for _ in range(H)]
cls = [[""] * W for _ in range(H)]


def put(x, y, ch, c):
    if 0 <= x < W and 0 <= y < H:
        grid[y][x] = ch
        cls[y][x] = c


# ---- stars ---------------------------------------------------------------
for _ in range(70):
    x, y = random.randrange(W), random.randrange(0, 16)
    put(x, y, random.choice(".....`'+"), "s")

# ---- moon (chars are ~2x taller than wide) -------------------------------
mcx, mcy, mr = 124, 7.5, 7.2
ramp = " .:-=+*%#@"
craters = [(-2.2, -1.5, 1.2), (1.8, 1.6, 1.5), (2.6, -2.4, 0.8), (-1.0, 3.0, 0.9)]
for y in range(H):
    for x in range(W):
        dx = (x - mcx) / 2.1
        dy = y - mcy
        d = math.hypot(dx, dy)
        if d > mr:
            continue
        # light from upper right, soft limb darkening
        nz = math.sqrt(max(0.0, 1 - (d / mr) ** 2))
        light = 0.55 * nz + 0.45 * max(0.0, (dx * 0.6 - dy * 0.5) / mr + 0.55)
        for cx, cy, cr in craters:
            if math.hypot(dx - cx, dy - cy) < cr:
                light *= 0.62
        i = max(1, min(len(ramp) - 1, int(light * (len(ramp) - 1) + 0.5)))
        put(x, y, ramp[i], "m")

# ---- skyline -------------------------------------------------------------
ground = H - 1
roof = [ground] * W
x = 0
buildings = []
heights = [6, 10, 4, 8, 13, 7, 5, 11, 6, 9, 3, 12, 7, 5, 9]
widths = [11, 16, 8, 14, 10, 18, 9, 15, 12, 10, 7, 13, 11, 9, 14]
i = 0
while x < W:
    bw, bh = widths[i % len(widths)], heights[i % len(heights)]
    buildings.append((x, min(W - 1, x + bw - 1), ground - bh))
    x += bw + (1 if i % 3 == 0 else 0)
    i += 1
# hand-tune a few heights so the poles and cat have places to stand
lit_windows = []
for bx0, bx1, top in buildings:
    for xx in range(bx0, bx1 + 1):
        roof[xx] = min(roof[xx], top)
    for xx in range(bx0, bx1 + 1):
        put(xx, top, "_", "b")
    for yy in range(top + 1, ground + 1):
        put(bx0, yy, "|", "b")
        put(bx1, yy, "|", "b")
    for yy in range(top + 2, ground, 2):
        for xx in range(bx0 + 2, bx1 - 1, 3):
            if random.random() < 0.14:
                put(xx, yy, "#", "l")
                lit_windows.append((xx, yy))
            else:
                put(xx, yy, ".", "b")
for xx in range(W):
    if grid[ground][xx] == " ":
        put(xx, ground, "_", "b")

# ---- poles + wires -------------------------------------------------------
poles = [20, 90]
arm_y = [10, 12]
arm = 5
for px in poles:
    base = roof[px]
    for yy in range(arm_y[0] - 1, base):
        put(px, yy, "|", "p")
    for ay in arm_y:
        for xx in range(px - arm, px + arm + 1):
            put(xx, ay, "=", "p")
        put(px - arm, ay - 1, "o", "p")
        put(px + arm, ay - 1, "o", "p")
        put(px, ay, "+", "p")
    put(px, arm_y[0] - 2, "^", "p")


def wire(x0, y0, x1, y1, sag):
    """Parabolic sag from (x0,y0) to (x1,y1); '-' / '_' give sub-row smoothness."""
    for x in range(min(x0, x1), max(x0, x1) + 1):
        t = (x - x0) / float(x1 - x0) if x1 != x0 else 0
        y = y0 + (y1 - y0) * t + sag * 4 * t * (1 - t)
        slope = (y1 - y0) / float(x1 - x0) + sag * 4 * (1 - 2 * t) / float(x1 - x0)
        row = int(math.floor(y))
        frac = y - row
        if abs(slope) > 0.55:
            ch = "\\" if slope > 0 else "/"
            row = int(round(y))
        elif frac < 0.5:
            ch = "-"
        else:
            ch = "_"
        if 0 <= row < H and 0 <= x < W and cls[row][x] != "p":
            put(x, row, ch, "w")


# wires hang between the insulators and run off both edges
# top arm: both insulators; lower arm: left one only. Only two wires cross the
# moon, so it stays readable.
spans = [(arm_y[0], -arm, 3.4, True), (arm_y[0], arm, 3.0, True), (arm_y[1], -arm, 4.2, False)]
for ay, side, sag, over_moon in spans:
    ya = ay - 1
    a = poles[0] + side
    b = poles[1] + side
    wire(a, ya, b, ya, sag)                         # span between poles
    wire(-40 + side, ya - 3, a, ya, 2.4)            # off-screen left
    if over_moon:
        wire(b, ya, W + 40 + side, ya - 7, 4.0)     # off-screen right, across the moon

# ---- cat on a roof -------------------------------------------------------
cat = [" /\\_/\\ ", "( -.- )", " > ^ < "]
cat_x = 139  # on the rooftop under the moon
cat_top = min(roof[cat_x:cat_x + 7]) - len(cat)
for r, line in enumerate(cat):
    for c, ch in enumerate(line):
        if ch != " ":
            put(cat_x + c, cat_top + r, ch, "c")

# ---- the one green window (closest lit window to the cat's building) ------
cands = sorted(lit_windows, key=lambda p: abs(p[0] - 142) + abs(p[1] - (H - 8)) * 2)
gx, gy = cands[0]
put(gx, gy, "#", "g")


def esc(ch):
    return {"<": "&lt;", ">": "&gt;", "&": "&amp;"}.get(ch, ch)


out = []
for y in range(H):
    line, cur, buf = [], None, ""
    for x in range(W):
        c = cls[y][x] if grid[y][x] != " " else None
        if c != cur:
            if buf:
                line.append('<i class="%s">%s</i>' % (cur, buf) if cur else buf)
            cur, buf = c, ""
        buf += esc(grid[y][x])
    if buf:
        line.append('<i class="%s">%s</i>' % (cur, buf) if cur else buf)
    text = "".join(line).rstrip()
    out.append(text if text else ".")
print("\n".join(out))
