from PIL import Image, ImageDraw, ImageFont
import numpy as np

font = ImageFont.truetype('editundo.ttf', 60)

# Step 1: Render reference digits (single, no calt context)
ref_arrays = {}
for d in range(10):
    img = Image.new('L', (50, 80), 255)
    draw = ImageDraw.Draw(img)
    draw.text((5, 5), str(d), font=font, fill=0, features=['-calt'])
    arr = np.array(img)
    # Crop to bounding box
    rows = np.any(arr < 128, axis=1)
    cols = np.any(arr < 128, axis=0)
    if rows.any() and cols.any():
        rmin, rmax = np.where(rows)[0][[0, -1]]
        cmin, cmax = np.where(cols)[0][[0, -1]]
        ref_arrays[d] = arr[rmin:rmax+1, cmin:cmax+1]

def identify_digit(crop_arr):
    """Compare cropped digit to references, return best match"""
    best_match = -1
    best_score = float('inf')
    for d, ref_arr in ref_arrays.items():
        # Resize crop to match ref
        from PIL import Image as PILImg
        crop_img = PILImg.fromarray(crop_arr)
        crop_resized = crop_img.resize((ref_arr.shape[1], ref_arr.shape[0]), PILImg.NEAREST)
        crop_r = np.array(crop_resized)
        diff = np.sum(np.abs(crop_r.astype(float) - ref_arr.astype(float)))
        if diff < best_score:
            best_score = diff
            best_match = d
    return best_match, best_score

def extract_digits_from_captcha(text):
    """Render captcha text with calt and identify the visual digits"""
    img = Image.new('L', (500, 80), 255)
    draw = ImageDraw.Draw(img)
    draw.text((10, 5), text, font=font, fill=0)  # default has calt on
    
    arr = np.array(img)
    
    # Find columns with dark pixels to segment characters
    col_has_dark = np.any(arr < 128, axis=0)
    
    # Find character boundaries
    chars = []
    in_char = False
    start = 0
    for x in range(arr.shape[1]):
        if col_has_dark[x] and not in_char:
            start = x
            in_char = True
        elif not col_has_dark[x] and in_char:
            chars.append((start, x))
            in_char = False
    if in_char:
        chars.append((start, arr.shape[1]))
    
    # Find vertical bounds
    rows = np.any(arr < 128, axis=1)
    rmin, rmax = np.where(rows)[0][[0, -1]]
    
    results = []
    for (cmin, cmax) in chars:
        crop = arr[rmin:rmax+1, cmin:cmax]
        d, score = identify_digit(crop)
        results.append((d, score))
    
    return results

# Step 2: Build the mapping for left-side (AB) and right-side (CD) two-digit numbers
# For left side, render "AB+00" and extract first two digits
# For right side, render "00+CD" and extract last two digits

print("Building left-side mapping (AB part)...")
left_map = {}  # (a, b) -> (visual_a, visual_b)
for ab in range(100):
    a, b = ab // 10, ab % 10
    text = f"{a}{b}+00"
    results = extract_digits_from_captcha(text)
    # results should have 5 chars: a, b, +, 0, 0
    # But + might be two segments or one
    # Let's identify: we need first 2 digits and ignore +00
    if len(results) >= 2:
        left_map[(a, b)] = (results[0][0], results[1][0])

print("Building right-side mapping (CD part)...")  
right_map = {}  # (c, d) -> (visual_c, visual_d)
for cd in range(100):
    c, d = cd // 10, cd % 10
    text = f"00+{c}{d}"
    results = extract_digits_from_captcha(text)
    # results should have 5 chars: 0, 0, +, c, d
    # We need the last 2 digits
    if len(results) >= 2:
        right_map[(c, d)] = (results[-2][0], results[-1][0])

# Print mappings
print("\nLeft-side mapping (source AB -> visual AB):")
for (a, b), (va, vb) in sorted(left_map.items()):
    print(f"  {a}{b} -> {va}{vb}")

print("\nRight-side mapping (source CD -> visual CD):")
for (c, d), (vc, vd) in sorted(right_map.items()):
    print(f"  {c}{d} -> {vc}{vd}")

# Build the complete solution table: for source "AB+CD", visual is "VA VB + VC VD"
# The server expects: visual_answer = VA*10+VB + VC*10+VD
print("\nSolution lookup table (source_expression -> visual_sum):")
solutions = {}
for ab in range(0, 100):  # include all from 00-99
    a, b = ab // 10, ab % 10
    if (a, b) not in left_map:
        continue
    va, vb = left_map[(a, b)]
    for cd in range(0, 100):
        c, d = cd // 10, cd % 10
        if (c, d) not in right_map:
            continue
        vc, vd = right_map[(c, d)]
        visual_left = va * 10 + vb
        visual_right = vc * 10 + vd
        visual_sum = visual_left + visual_right
        key = f"{a}{b}+{c}{d}"
        solutions[key] = visual_sum

# Save the solutions dict
import json
with open('captcha_solutions.json', 'w') as f:
    json.dump(solutions, f)
print(f"\nSaved {len(solutions)} solutions to captcha_solutions.json")

# Test a few
for test in ["17+43", "51+76", "70+71"]:
    if test in solutions:
        print(f"  {test} -> visual answer: {solutions[test]}")
