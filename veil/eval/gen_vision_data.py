"""
Synthetic Vision Data & Evaluation Corpus Generator (Task 1).
Generates:
1. Synthetic ID images (Aadhaar, PAN, Marksheet, Bank Statement) in English and Hindi.
   - Stamped 'SAMPLE - SYNTHETIC'.
   - Valid-format numbers (Verhoeff checksum for Aadhaar, Luhn for cards, valid PAN/IFSC).
   - Augmentation variants: clean, rotated (0-5 deg), blurred, low-res, JPEG artifacts, dark mode, small font, photo of screen.
2. Synthetic Face dataset with diverse ages, skin tones, glasses, masks, profiles, group photos.
3. Hard Negatives: animals, statues, cartoons, logos, posters, non-PII text, checksum-failing number tables.
4. 100 HTML evaluation pages (60 dev + 40 held-out) embedding images via img, canvas, background-image, video poster, and iframe PDF.
5. Ground truth manifest (ground_truth.json) with bounding boxes for all faces and PII text.
"""

import os
import math
import json
import random
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageEnhance

# Set random seed for reproducibility
random.seed(42)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "vision_data"
IDS_DIR = DATA_DIR / "ids"
FACES_DIR = DATA_DIR / "faces"
NEG_DIR = DATA_DIR / "hard_negatives"
PAGES_DIR = BASE_DIR / "vision_pages"

for d in [DATA_DIR, IDS_DIR, FACES_DIR, NEG_DIR, PAGES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Verhoeff algorithm for valid fake Aadhaar generation
D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]
P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]
INV_TABLE = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def generate_verhoeff_aadhaar():
    first = str(random.randint(2, 9))
    rest_10 = "".join([str(random.randint(0, 9)) for _ in range(10)])
    num_11 = first + rest_10
    c = 0
    reversed_digits = [int(x) for x in reversed(num_11)]
    for i, digit in enumerate(reversed_digits):
        p_row = P_TABLE[(i + 1) % 8]
        c = D_TABLE[c][p_row[digit]]
    check_digit = INV_TABLE[c]
    return f"{num_11}{check_digit}"

def generate_luhn_card():
    prefix = random.choice(["4532", "5521", "3782"])
    remaining = 16 - len(prefix) - 1
    digits = [int(x) for x in prefix] + [random.randint(0, 9) for _ in range(remaining)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            m = d * 2
            total += (m - 9) if m > 9 else m
        else:
            total += d
    check = (10 - (total % 10)) % 10
    full_digits = digits + [check]
    return "".join(map(str, full_digits))

# System fonts with fallback
def get_fonts(size=14, is_hindi=False):
    hindi_paths = ["C:/Windows/Fonts/Nirmala.ttc", "C:/Windows/Fonts/mangal.ttf"]
    latin_paths = ["C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/segoeui.ttf"]
    
    font_path = None
    if is_hindi:
        for p in hindi_paths:
            if os.path.exists(p):
                font_path = p
                break
    if not font_path:
        for p in latin_paths:
            if os.path.exists(p):
                font_path = p
                break
                
    if font_path:
        try:
            return ImageFont.truetype(font_path, size)
        except Exception:
            pass
    return ImageFont.load_default()

# 1. Procedural Face Generator for synthetic profile photos
def draw_synthetic_face(draw, box, attrs=None):
    """Draws a procedural vector portrait within bounding box [x, y, w, h]."""
    x, y, w, h = box
    attrs = attrs or {}
    skin_tones = [
        (255, 224, 189), (234, 192, 134), (255, 205, 148),
        (198, 134, 66), (141, 85, 36), (106, 58, 20)
    ]
    skin = attrs.get("skin_tone", random.choice(skin_tones))
    
    # Head / Face oval
    head_pad = int(w * 0.12)
    face_box = [x + head_pad, y + head_pad, x + w - head_pad, y + h - head_pad]
    draw.ellipse(face_box, fill=skin, outline=(40, 40, 40), width=2)
    
    # Hair
    hair_color = attrs.get("hair_color", (30, 20, 15))
    hair_top = [face_box[0] - 2, face_box[1] - 4, face_box[2] + 2, face_box[1] + int(h * 0.35)]
    draw.chord(hair_top, start=180, end=360, fill=hair_color)
    
    # Eyes
    eye_y = y + int(h * 0.42)
    eye_w = max(3, int(w * 0.08))
    left_eye = [x + int(w * 0.32), eye_y, x + int(w * 0.32) + eye_w, eye_y + eye_w]
    right_eye = [x + int(w * 0.60), eye_y, x + int(w * 0.60) + eye_w, eye_y + eye_w]
    draw.ellipse(left_eye, fill=(20, 20, 20))
    draw.ellipse(right_eye, fill=(20, 20, 20))
    
    # Eyeglasses
    if attrs.get("glasses", False):
        g_pad = 3
        draw.ellipse([left_eye[0] - g_pad, eye_y - g_pad, left_eye[2] + g_pad, eye_y + eye_w + g_pad], outline=(20, 20, 20), width=2)
        draw.ellipse([right_eye[0] - g_pad, eye_y - g_pad, right_eye[2] + g_pad, eye_y + eye_w + g_pad], outline=(20, 20, 20), width=2)
        draw.line([left_eye[2] + g_pad, eye_y + eye_w//2, right_eye[0] - g_pad, eye_y + eye_w//2], fill=(20, 20, 20), width=2)
        
    # Mask
    if attrs.get("mask", False):
        mask_box = [face_box[0] + 4, y + int(h * 0.52), face_box[2] - 4, face_box[3] - 4]
        draw.rectangle(mask_box, fill=(180, 220, 240), outline=(100, 140, 180), width=2)
    else:
        # Mouth / Nose
        nose_y = y + int(h * 0.54)
        draw.line([x + w//2, nose_y, x + w//2, nose_y + int(h * 0.08)], fill=(80, 40, 20), width=2)
        mouth_y = y + int(h * 0.70)
        draw.arc([x + int(w * 0.38), mouth_y, x + int(w * 0.62), mouth_y + int(h * 0.10)], start=0, end=180, fill=(150, 40, 40), width=2)

def stamp_sample(draw, width, height, is_dark=False):
    stamp_text = "SAMPLE - SYNTHETIC"
    font = get_fonts(size=22)
    color = (255, 60, 60, 160) if is_dark else (200, 30, 30)
    draw.text((width // 2 - 110, height - 32), stamp_text, font=font, fill=color)

# Augmentations generator
def apply_augmentations(base_img, variant):
    w, h = base_img.size
    if variant == "clean":
        return base_img
    elif variant == "rotated":
        # Rotated 3 degrees
        rot = base_img.rotate(3.5, expand=True, resample=Image.BICUBIC, fillcolor=(255, 255, 255))
        return rot
    elif variant == "blur":
        return base_img.filter(ImageFilter.GaussianBlur(radius=2.0))
    elif variant == "lowres":
        small = base_img.resize((w // 3, h // 3), Image.BILINEAR)
        return small.resize((w, h), Image.NEAREST)
    elif variant == "jpeg":
        # High compression artifacts
        import io
        buf = io.BytesIO()
        base_img.save(buf, format="JPEG", quality=28)
        buf.seek(0)
        return Image.open(buf)
    elif variant == "darkmode":
        # Invert colors or dark theme
        return ImageEnhance.Brightness(base_img).enhance(0.4)
    elif variant == "smallfont":
        return base_img.resize((int(w * 0.7), int(h * 0.7)), Image.BICUBIC)
    elif variant == "screen_photo":
        # Simulate moire and screen lines
        res = base_img.copy()
        draw = ImageDraw.Draw(res)
        for i in range(0, h, 4):
            draw.line([(0, i), (w, i)], fill=(0, 0, 0), width=1)
        res = ImageEnhance.Color(res).enhance(0.8)
        return res
    return base_img

# --- 2. Generate Synthetic ID Documents ---
id_manifest = []

def generate_aadhaar_card(name, aadhaar_num, mobile_num, is_hindi=False):
    w, h = 500, 310
    img = Image.new("RGB", (w, h), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    
    # Border & Header
    draw.rectangle([4, 4, w - 5, h - 5], outline=(15, 118, 110), width=3)
    draw.rectangle([6, 6, w - 7, 45], fill=(224, 242, 254))
    
    header_font = get_fonts(16, is_hindi)
    body_font = get_fonts(13, is_hindi)
    num_font = get_fonts(18)
    
    header_text = "भारत सरकार / Government of India" if is_hindi else "Government of India - Unique Identification Authority"
    draw.text((16, 14), header_text, font=header_font, fill=(15, 23, 42))
    
    # Face photo box
    face_box = [20, 60, 110, 130] # x, y, w, h
    draw.rectangle([20, 60, 130, 190], fill=(240, 245, 250), outline=(100, 116, 139), width=2)
    draw_synthetic_face(draw, [20, 60, 110, 130], {"glasses": random.choice([True, False])})
    
    # Details
    lbl_name = "नाम / Name:" if is_hindi else "Name:"
    draw.text((150, 65), f"{lbl_name} {name}", font=body_font, fill=(15, 23, 42))
    draw.text((150, 95), "DOB: 15/08/1990", font=body_font, fill=(15, 23, 42))
    draw.text((150, 125), "Gender: MALE", font=body_font, fill=(15, 23, 42))
    draw.text((150, 155), f"Mobile: {mobile_num}", font=body_font, fill=(15, 23, 42))
    
    # Aadhaar Number (segmented)
    formatted_aadhaar = f"{aadhaar_num[:4]} {aadhaar_num[4:8]} {aadhaar_num[8:]}"
    draw.text((140, 210), formatted_aadhaar, font=num_font, fill=(185, 28, 28))
    
    stamp_sample(draw, w, h)
    
    pii_entries = [
        {"type": "aadhaar", "text": aadhaar_num, "bbox": [140, 210, 190, 25]},
        {"type": "mobile", "text": mobile_num, "bbox": [150, 155, 140, 18]}
    ]
    face_entries = [{"category": "standard", "bbox": [20, 60, 110, 130]}]
    return img, pii_entries, face_entries

def generate_pan_card(name, pan_num):
    w, h = 480, 290
    img = Image.new("RGB", (w, h), color=(248, 250, 252))
    draw = ImageDraw.Draw(img)
    
    draw.rectangle([4, 4, w - 5, h - 5], outline=(30, 41, 59), width=3)
    draw.rectangle([6, 6, w - 7, 40], fill=(219, 234, 254))
    
    h_font = get_fonts(15)
    b_font = get_fonts(13)
    num_font = get_fonts(17)
    
    draw.text((16, 12), "INCOME TAX DEPARTMENT - GOVT OF INDIA", font=h_font, fill=(30, 58, 138))
    
    # Face photo box
    draw.rectangle([20, 55, 120, 185], fill=(230, 235, 240), outline=(100, 116, 139), width=2)
    draw_synthetic_face(draw, [20, 55, 100, 130], {"skin_tone": (234, 192, 134)})
    
    draw.text((140, 60), f"Name: {name}", font=b_font, fill=(15, 23, 42))
    draw.text((140, 95), "Father's Name: SURESH VERMA", font=b_font, fill=(15, 23, 42))
    draw.text((140, 130), "Date of Birth: 12/04/1988", font=b_font, fill=(15, 23, 42))
    
    # PAN Number
    draw.text((140, 180), f"PAN: {pan_num}", font=num_font, fill=(2, 132, 199))
    
    stamp_sample(draw, w, h)
    
    pii_entries = [{"type": "pan", "text": pan_num, "bbox": [140, 180, 160, 24]}]
    face_entries = [{"category": "standard", "bbox": [20, 55, 100, 130]}]
    return img, pii_entries, face_entries

def generate_bank_statement(name, ifsc_code, card_num):
    w, h = 550, 360
    img = Image.new("RGB", (w, h), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    
    draw.rectangle([4, 4, w - 5, h - 5], outline=(100, 116, 139), width=2)
    draw.rectangle([6, 6, w - 7, 45], fill=(241, 245, 249))
    
    h_font = get_fonts(16)
    b_font = get_fonts(12)
    
    draw.text((16, 14), "STATE BANK DEMO - ACCOUNT STATEMENT", font=h_font, fill=(30, 41, 59))
    
    draw.text((20, 60), f"Account Holder: {name}", font=b_font, fill=(15, 23, 42))
    draw.text((20, 85), f"Branch IFSC: {ifsc_code}", font=b_font, fill=(15, 23, 42))
    draw.text((20, 110), f"Linked Card: {card_num[:4]} {card_num[4:8]} {card_num[8:12]} {card_num[12:]}", font=b_font, fill=(15, 23, 42))
    draw.text((20, 135), "Account Number: 987654321012 (Savings)", font=b_font, fill=(15, 23, 42))
    
    # Table header
    draw.line([(20, 165), (w - 20, 165)], fill=(148, 163, 184), width=1)
    draw.text((25, 175), "Date", font=b_font, fill=(71, 85, 105))
    draw.text((120, 175), "Description", font=b_font, fill=(71, 85, 105))
    draw.text((330, 175), "Debit", font=b_font, fill=(71, 85, 105))
    draw.text((430, 175), "Balance", font=b_font, fill=(71, 85, 105))
    draw.line([(20, 195), (w - 20, 195)], fill=(148, 163, 184), width=1)
    
    # Rows
    draw.text((25, 205), "2026-09-01", font=b_font, fill=(30, 41, 59))
    draw.text((120, 205), "UPI/merchant@okaxis", font=b_font, fill=(30, 41, 59))
    draw.text((330, 205), "₹ 1,200.00", font=b_font, fill=(30, 41, 59))
    draw.text((430, 205), "₹ 54,230.00", font=b_font, fill=(30, 41, 59))
    
    stamp_sample(draw, w, h)
    
    pii_entries = [
        {"type": "ifsc", "text": ifsc_code, "bbox": [20, 85, 160, 18]},
        {"type": "card", "text": card_num, "bbox": [20, 110, 220, 18]},
        {"type": "upi", "text": "merchant@okaxis", "bbox": [120, 205, 130, 18]}
    ]
    return img, pii_entries, []

# Generate all ID types and augmentations
id_configs = [
    ("aadhaar_en", lambda: generate_aadhaar_card("Asha Verma", generate_verhoeff_aadhaar(), "+91 98765 43210", is_hindi=False)),
    ("aadhaar_hi", lambda: generate_aadhaar_card("आशा वर्मा", generate_verhoeff_aadhaar(), "+91 91234 56789", is_hindi=True)),
    ("pan_card", lambda: generate_pan_card("ROHIT KUMAR", "ABCPK1234F")),
    ("bank_statement", lambda: generate_bank_statement("Asha Verma", "SBIN0001234", generate_luhn_card()))
]

variants = ["clean", "rotated", "blur", "lowres", "jpeg", "darkmode", "smallfont", "screen_photo"]
ground_truth = {"images": {}, "pages": {}}

total_ids_generated = 0
for base_name, gen_fn in id_configs:
    base_img, pii_items, face_items = gen_fn()
    for var in variants:
        img_name = f"{base_name}_{var}.png" if var != "jpeg" else f"{base_name}_{var}.jpg"
        out_img = apply_augmentations(base_img, var)
        out_path = IDS_DIR / img_name
        if var == "jpeg":
            out_img.save(out_path, format="JPEG", quality=28)
        else:
            out_img.save(out_path, format="PNG")
        
        ground_truth["images"][img_name] = {
            "type": base_name,
            "variant": var,
            "width": out_img.width,
            "height": out_img.height,
            "pii": pii_items,
            "faces": face_items,
            "is_hard_negative": False
        }
        total_ids_generated += 1

print(f"Generated {total_ids_generated} synthetic ID document images with augmentations.")

# --- 3. Generate Diverse Faces Dataset ---
face_categories = [
    ("face_young_light", {"skin_tone": (255, 224, 189), "glasses": False, "mask": False}),
    ("face_young_medium", {"skin_tone": (234, 192, 134), "glasses": False, "mask": False}),
    ("face_young_deep", {"skin_tone": (141, 85, 36), "glasses": False, "mask": False}),
    ("face_glasses_light", {"skin_tone": (255, 205, 148), "glasses": True, "mask": False}),
    ("face_glasses_dark", {"skin_tone": (106, 58, 20), "glasses": True, "mask": False}),
    ("face_mask_light", {"skin_tone": (255, 224, 189), "glasses": False, "mask": True}),
    ("face_mask_deep", {"skin_tone": (141, 85, 36), "glasses": False, "mask": True}),
    ("face_elder_light", {"skin_tone": (245, 215, 180), "hair_color": (200, 200, 200), "glasses": True}),
    ("face_elder_deep", {"skin_tone": (120, 70, 30), "hair_color": (180, 180, 180), "glasses": False}),
    ("face_profile_left", {"skin_tone": (234, 192, 134), "profile": "left"}),
]

total_faces_generated = 0
for cat_name, attrs in face_categories:
    # Single face portrait
    img = Image.new("RGB", (240, 240), color=(240, 244, 248))
    draw = ImageDraw.Draw(img)
    face_box = [30, 25, 180, 190]
    draw_synthetic_face(draw, face_box, attrs)
    
    img_name = f"{cat_name}.png"
    img.save(FACES_DIR / img_name)
    ground_truth["images"][img_name] = {
        "type": "face",
        "faces": [{"category": cat_name, "bbox": face_box}],
        "pii": [],
        "is_hard_negative": False
    }
    total_faces_generated += 1

# Group photo with 3 small faces
group_img = Image.new("RGB", (480, 260), color=(245, 248, 252))
g_draw = ImageDraw.Draw(group_img)
g_faces = [
    [40, 60, 90, 110],
    [190, 50, 100, 120],
    [340, 65, 85, 105]
]
for i, f_box in enumerate(g_faces):
    draw_synthetic_face(g_draw, f_box, {"glasses": i == 1})

group_img.save(FACES_DIR / "faces_group_photo.png")
ground_truth["images"]["faces_group_photo.png"] = {
    "type": "face_group",
    "faces": [{"category": "small_face", "bbox": fb} for fb in g_faces],
    "pii": [],
    "is_hard_negative": False
}
total_faces_generated += 1

print(f"Generated {total_faces_generated} synthetic face assets (diverse skin tones, glasses, masks, groups).")

# --- 4. Generate Hard Negatives ---
neg_specs = [
    ("neg_geometric_logo", "logo"),
    ("neg_statue_silhouette", "statue"),
    ("neg_abstract_art", "poster"),
    ("neg_animal_silhouette", "animal"),
    ("neg_nonpii_text", "text"),
    ("neg_invalid_numbers_table", "invalid_numbers"),
    ("neg_scenery_landscape", "landscape"),
    ("neg_circuit_diagram", "diagram")
]

total_negs_generated = 0
for neg_name, n_type in neg_specs:
    img = Image.new("RGB", (320, 240), color=(250, 250, 250))
    draw = ImageDraw.Draw(img)
    
    if n_type == "logo":
        draw.ellipse([80, 40, 240, 200], fill=(2, 132, 199))
        draw.rectangle([130, 90, 190, 150], fill=(255, 255, 255))
        draw.text((100, 210), "SYNTHETIC LOGO", fill=(30, 41, 59))
    elif n_type == "statue":
        draw.rectangle([110, 40, 210, 180], fill=(160, 160, 160))
        draw.rectangle([80, 180, 240, 220], fill=(100, 100, 100))
        draw.text((95, 222), "HISTORICAL MONUMENT", fill=(40, 40, 40))
    elif n_type == "animal":
        # Draw abstract animal shape (cat/bird)
        draw.ellipse([100, 80, 220, 170], fill=(180, 120, 60))
        draw.polygon([(110, 80), (130, 40), (150, 80)], fill=(180, 120, 60))
        draw.polygon([(170, 80), (190, 40), (210, 80)], fill=(180, 120, 60))
        draw.text((110, 200), "ANIMAL WILDLIFE", fill=(40, 40, 40))
    elif n_type == "invalid_numbers":
        # Numbers deliberately failing Luhn and Verhoeff
        font = get_fonts(11)
        draw.text((20, 20), "BATCH RUN STATS (NOT PII)", font=font, fill=(0, 0, 0))
        draw.text((20, 50), "Timestamp: 2026-09-28T19:42:01Z", font=font, fill=(0, 0, 0))
        draw.text((20, 75), "Order Ref: ORD-993847192847", font=font, fill=(0, 0, 0))
        draw.text((20, 100), "ISBN-13: 978-3-16-148410-0", font=font, fill=(0, 0, 0))
        draw.text((20, 125), "Luhn-Fail Card: 4532 0151 1283 0367", font=font, fill=(0, 0, 0))
        draw.text((20, 150), "Verhoeff-Fail Aadhaar: 2345 6789 0125", font=font, fill=(0, 0, 0))
        draw.text((20, 175), "Serial UUID: e82f1b4a-9c71", font=font, fill=(0, 0, 0))
    else:
        # Abstract pattern / landscape
        draw.rectangle([0, 0, 320, 120], fill=(125, 211, 252))
        draw.rectangle([0, 120, 320, 240], fill=(74, 222, 128))
        draw.ellipse([230, 30, 290, 90], fill=(253, 224, 71))
        
    img_name = f"{neg_name}.png"
    img.save(NEG_DIR / img_name)
    ground_truth["images"][img_name] = {
        "type": n_type,
        "faces": [],
        "pii": [],
        "is_hard_negative": True
    }
    total_negs_generated += 1

print(f"Generated {total_negs_generated} hard-negative test images.")

# --- 5. Generate 100 Vision Evaluation Pages (60 Dev + 40 Held-Out) ---
all_id_files = sorted(list(IDS_DIR.glob("*.*")))
all_face_files = sorted(list(FACES_DIR.glob("*.png")))
all_neg_files = sorted(list(NEG_DIR.glob("*.png")))

def generate_pages(split_name, count):
    pages = []
    for i in range(1, count + 1):
        page_id = f"{split_name}_{i:03d}"
        
        # Pick 1 ID image, 1 face, 1 hard negative
        id_f = all_id_files[(i * 3) % len(all_id_files)]
        face_f = all_face_files[(i * 5) % len(all_face_files)]
        neg_f = all_neg_files[(i * 7) % len(all_neg_files)]
        
        # Determine embedding methods (img, canvas, background-image, video poster, iframe)
        embed_mode = ["img_standard", "canvas_draw", "css_bg", "video_poster", "iframe_pdf"][i % 5]
        
        html_content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vision Test {page_id}</title>
  <style>
    body {{ font: 14px system-ui; max-width: 800px; margin: 20px auto; }}
    .media-card {{ margin-bottom: 20px; padding: 12px; border: 1px solid #cbd5e1; border-radius: 8px; }}
    .bg-container {{ width: 480px; height: 290px; background-image: url('../vision_data/ids/{id_f.name}'); background-size: cover; }}
  </style>
</head>
<body>
  <h2>Vision Privacy Verification Page: {page_id}</h2>
  <p>Mode: {embed_mode}</p>
"""
        page_elements = []
        
        if embed_mode == "img_standard":
            html_content += f"""
  <div class="media-card">
    <h3>ID Document</h3>
    <img id="img_id" src="../vision_data/ids/{id_f.name}" alt="Identity Document">
  </div>
  <div class="media-card">
    <h3>Profile Portrait</h3>
    <img id="img_face" src="../vision_data/faces/{face_f.name}" alt="User Avatar">
  </div>
  <div class="media-card">
    <h3>Harmless Illustration</h3>
    <img id="img_neg" src="../vision_data/hard_negatives/{neg_f.name}" alt="Illustration">
  </div>
"""
            page_elements.extend([id_f.name, face_f.name, neg_f.name])
            
        elif embed_mode == "canvas_draw":
            html_content += f"""
  <div class="media-card">
    <h3>Canvas Rendered ID</h3>
    <canvas id="canvas_id" width="500" height="310"></canvas>
    <script>
      const c = document.getElementById('canvas_id');
      const ctx = c.getContext('2d');
      const img = new Image();
      img.onload = () => ctx.drawImage(img, 0, 0);
      img.src = '../vision_data/ids/{id_f.name}';
    </script>
  </div>
  <div class="media-card">
    <h3>Harmless Graphic</h3>
    <img src="../vision_data/hard_negatives/{neg_f.name}">
  </div>
"""
            page_elements.extend([id_f.name, neg_f.name])
            
        elif embed_mode == "css_bg":
            html_content += f"""
  <div class="media-card">
    <h3>CSS Background Image ID</h3>
    <div id="div_bg" class="bg-container"></div>
  </div>
  <div class="media-card">
    <h3>User Profile</h3>
    <img src="../vision_data/faces/{face_f.name}">
  </div>
"""
            page_elements.extend([id_f.name, face_f.name])
            
        elif embed_mode == "video_poster":
            html_content += f"""
  <div class="media-card">
    <h3>Video Frame Poster</h3>
    <video id="vid_poster" poster="../vision_data/ids/{id_f.name}" width="500" height="310" controls></video>
  </div>
  <div class="media-card">
    <h3>Harmless Banner</h3>
    <img src="../vision_data/hard_negatives/{neg_f.name}">
  </div>
"""
            page_elements.extend([id_f.name, neg_f.name])
            
        elif embed_mode == "iframe_pdf":
            html_content += f"""
  <div class="media-card">
    <h3>Simulated PDF / Iframe Viewer</h3>
    <iframe id="iframe_doc" src="../vision_data/ids/{id_f.name}" width="550" height="360"></iframe>
  </div>
  <div class="media-card">
    <h3>Profile Portrait</h3>
    <img src="../vision_data/faces/{face_f.name}">
  </div>
"""
            page_elements.extend([id_f.name, face_f.name])

        html_content += "\n</body>\n</html>\n"
        
        file_path = PAGES_DIR / f"{page_id}.html"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        ground_truth["pages"][f"{page_id}.html"] = {
            "split": split_name,
            "embed_mode": embed_mode,
            "elements": page_elements
        }
        pages.append(f"{page_id}.html")
    return pages

dev_pages = generate_pages("dev", 60)
held_out_pages = generate_pages("held_out", 40)

# Save ground_truth.json
gt_path = DATA_DIR / "ground_truth.json"
with open(gt_path, "w", encoding="utf-8") as f:
    json.dump(ground_truth, f, indent=2)

print(f"Generated {len(dev_pages)} Dev pages and {len(held_out_pages)} Held-Out pages in {PAGES_DIR}.")
print(f"Saved complete vision ground truth manifest to {gt_path}.")
