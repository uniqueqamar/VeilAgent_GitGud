"""
Independent Synthetic Corpus Generator for Veil Agent (Task 5).
Generates:
- 60 Dev pages (eval/corpus/dev/)
- 40 Held-out pages (eval/corpus/held_out/)
- Ground-truth expected.json for both sets.

All identities, numbers, and documents are 100% synthetic and fictional.
Written independently with dedicated Verhoeff and Luhn implementations and Faker en_IN.
"""
import json
import random
from pathlib import Path
from faker import Faker

BASE_DIR = Path(__file__).resolve().parent
DEV_DIR = BASE_DIR / "corpus" / "dev"
HELD_OUT_DIR = BASE_DIR / "corpus" / "held_out"

# Independent Verhoeff Implementation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

DEVANAGARI_DIGITS = {
    '0': '०', '1': '१', '2': '२', '3': '३', '4': '४',
    '5': '५', '6': '६', '7': '७', '8': '८', '9': '९'
}

def to_devanagari(num_str: str) -> str:
    return "".join(DEVANAGARI_DIGITS.get(ch, ch) for ch in num_str)

def generate_verhoeff_aadhaar(rng: random.Random, valid: bool = True) -> str:
    # 12 digits, first digit 2-9
    first_digit = str(rng.randint(2, 9))
    middle = "".join(str(rng.randint(0, 9)) for _ in range(10))
    eleven = first_digit + middle
    c = 0
    for i, ch in enumerate(reversed(eleven)):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(ch)]]
    chk = VERHOEFF_INV[c]
    if valid:
        return eleven + str(chk)
    else:
        bad_chk = (chk + rng.randint(1, 9)) % 10
        return eleven + str(bad_chk)

def generate_luhn_card(rng: random.Random, valid: bool = True, length: int = 16) -> str:
    # Visa prefix 4, Mastercard 51-55, etc.
    prefix = rng.choice(["4", "51", "52", "55", "37"])
    rem_len = length - len(prefix) - 1
    middle = "".join(str(rng.randint(0, 9)) for _ in range(rem_len))
    body = prefix + middle
    # Calculate Luhn check digit
    s = 0
    alt = True
    for ch in reversed(body):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    chk = (10 - (s % 10)) % 10
    if valid:
        return body + str(chk)
    else:
        bad_chk = (chk + rng.randint(1, 9)) % 10
        return body + str(bad_chk)

def generate_pan(rng: random.Random) -> str:
    chars = [rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(3)]
    entity = rng.choice(["P", "C", "H", "F", "A", "T", "B", "L", "J", "G"])
    last_name_initial = rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits = f"{rng.randint(1000, 9999)}"
    last_char = rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return f"{''.join(chars)}{entity}{last_name_initial}{digits}{last_char}"

def generate_ifsc(rng: random.Random) -> str:
    bank = rng.choice(["HDFC", "SBIN", "ICIC", "UTIB", "KKBK", "BARB", "PUNB"])
    branch = "".join(rng.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(6))
    return f"{bank}0{branch}"

def generate_upi(rng: random.Random, fake: Faker) -> str:
    handle = fake.user_name().replace(".", "")[:12]
    provider = rng.choice(["okhdfcbank", "oksbi", "okaxis", "okicici", "paytm", "ybl", "upi", "ibl", "barodampay"])
    return f"{handle}@{provider}"

def generate_passport(rng: random.Random) -> str:
    letter = rng.choice("ABCDEFGJKLMNPRSTWYZ")
    digits = f"{rng.randint(1000000, 9999999)}"
    return f"{letter}{digits}"

def generate_voter_id(rng: random.Random) -> str:
    prefix = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(3))
    digits = f"{rng.randint(1000000, 9999999)}"
    return f"{prefix}{digits}"

def generate_dl(rng: random.Random) -> str:
    state = rng.choice(["DL", "MH", "KA", "TN", "UP", "GJ", "RJ", "WB", "KL", "AP"])
    rto = f"{rng.randint(1, 40):02d}"
    year = f"{rng.randint(1995, 2024)}"
    num = f"{rng.randint(1000000, 9999999)}"
    sep = rng.choice(["", "-", " "])
    return f"{state}{sep}{rto}{sep}{year}{sep}{num}"

def generate_plate(rng: random.Random) -> str:
    is_bh = rng.random() < 0.2
    if is_bh:
        yr = f"{rng.randint(21, 25):02d}"
        num = f"{rng.randint(1000, 9999)}"
        series = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(rng.randint(1, 2)))
        return f"{yr} BH {num} {series}"
    else:
        state = rng.choice(["DL", "MH", "KA", "TN", "UP", "GJ", "RJ", "WB", "KL", "AP"])
        district = f"{rng.randint(1, 99)}"
        series = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(rng.randint(1, 2)))
        num = f"{rng.randint(1000, 9999)}"
        sep = rng.choice([" ", "-", ""])
        return f"{state}{sep}{district}{sep}{series}{sep}{num}"

def generate_mobile(rng: random.Random) -> str:
    first = str(rng.randint(6, 9))
    rest = "".join(str(rng.randint(0, 9)) for _ in range(9))
    ten = first + rest
    style = rng.choice(["plain", "prefix_91", "prefix_plus91", "spaced", "hyphenated", "devanagari"])
    if style == "prefix_91":
        return f"91{ten}"
    elif style == "prefix_plus91":
        return f"+91 {ten[:5]} {ten[5:]}"
    elif style == "spaced":
        return f"{ten[:5]} {ten[5:]}"
    elif style == "hyphenated":
        return f"{ten[:5]}-{ten[5:]}"
    elif style == "devanagari":
        return f"+९१ {to_devanagari(ten[:5])} {to_devanagari(ten[5:])}"
    return ten

def generate_page(page_id: int, rng: random.Random, fake: Faker) -> tuple[str, list[dict]]:
    """Generates a synthetic HTML page with mixed positives, varied formatting, and hard negatives."""
    expected = []
    page_filename = f"page_{page_id:03d}.html"

    # Decide page category: 80% with PII, 20% negative-only pages
    has_pii = rng.random() > 0.2

    body_items = []

    if has_pii:
        # 1. Email
        if rng.random() > 0.3:
            email = fake.email()
            expected.append({"page": page_filename, "type": "email", "value": email, "location": "p", "category": "positive"})
            body_items.append(f"<p>Contact email: <span>{email}</span></p>")

        # 2. Mobile
        if rng.random() > 0.3:
            mobile = generate_mobile(rng)
            expected.append({"page": page_filename, "type": "mobile", "value": mobile, "location": "p", "category": "positive"})
            body_items.append(f"<p>Mobile: {mobile}</p>")

        # 3. Aadhaar
        if rng.random() > 0.3:
            aadhaar_raw = generate_verhoeff_aadhaar(rng, valid=True)
            fmt = rng.choice(["plain", "spaced", "hyphenated", "devanagari", "span_split"])
            if fmt == "spaced":
                val = f"{aadhaar_raw[:4]} {aadhaar_raw[4:8]} {aadhaar_raw[8:]}"
                body_items.append(f"<p>Aadhaar Number: {val}</p>")
                expected.append({"page": page_filename, "type": "aadhaar", "value": val, "location": "p", "category": "positive"})
            elif fmt == "hyphenated":
                val = f"{aadhaar_raw[:4]}-{aadhaar_raw[4:8]}-{aadhaar_raw[8:]}"
                body_items.append(f"<p>UIDAI: {val}</p>")
                expected.append({"page": page_filename, "type": "aadhaar", "value": val, "location": "p", "category": "positive"})
            elif fmt == "devanagari":
                dev = to_devanagari(f"{aadhaar_raw[:4]} {aadhaar_raw[4:8]} {aadhaar_raw[8:]}")
                body_items.append(f"<p>आधार कार्ड: {dev}</p>")
                expected.append({"page": page_filename, "type": "aadhaar", "value": dev, "location": "p", "category": "positive"})
            elif fmt == "span_split":
                val = f"{aadhaar_raw[:4]} {aadhaar_raw[4:8]} {aadhaar_raw[8:]}"
                body_items.append(f"<p>Aadhaar: <span>{aadhaar_raw[:4]}</span> <span>{aadhaar_raw[4:8]}</span> <span>{aadhaar_raw[8:]}</span></p>")
                expected.append({"page": page_filename, "type": "aadhaar", "value": val, "location": "p", "category": "positive"})
            else:
                val = aadhaar_raw
                body_items.append(f"<p>Aadhaar UID: {val}</p>")
                expected.append({"page": page_filename, "type": "aadhaar", "value": val, "location": "p", "category": "positive"})

        # 4. PAN
        if rng.random() > 0.4:
            pan = generate_pan(rng)
            loc = rng.choice(["p", "input_attr"])
            if loc == "input_attr":
                body_items.append(f'<input type="text" name="pan" placeholder="Enter PAN e.g. {pan}" aria-label="PAN: {pan}">')
                expected.append({"page": page_filename, "type": "pan", "value": pan, "location": "placeholder", "category": "positive"})
            else:
                body_items.append(f"<p>PAN Card: {pan}</p>")
                expected.append({"page": page_filename, "type": "pan", "value": pan, "location": "p", "category": "positive"})

        # 5. Payment Card
        if rng.random() > 0.4:
            card_raw = generate_luhn_card(rng, valid=True)
            spaced = f"{card_raw[:4]} {card_raw[4:8]} {card_raw[8:12]} {card_raw[12:]}"
            body_items.append(f"<p>Card Number: {spaced}</p>")
            expected.append({"page": page_filename, "type": "card", "value": spaced, "location": "p", "category": "positive"})

        # 6. IFSC
        if rng.random() > 0.5:
            ifsc = generate_ifsc(rng)
            body_items.append(f"<p>Branch IFSC Code: {ifsc}</p>")
            expected.append({"page": page_filename, "type": "ifsc", "value": ifsc, "location": "p", "category": "positive"})

        # 7. UPI
        if rng.random() > 0.5:
            upi = generate_upi(rng, fake)
            body_items.append(f"<p>UPI VPA: {upi}</p>")
            expected.append({"page": page_filename, "type": "upi", "value": upi, "location": "p", "category": "positive"})

        # 8. Passport
        if rng.random() > 0.6:
            passport = generate_passport(rng)
            body_items.append(f"<p>Passport Number: {passport}</p>")
            expected.append({"page": page_filename, "type": "passport", "value": passport, "location": "p", "category": "positive"})

        # 9. Voter ID
        if rng.random() > 0.6:
            voter = generate_voter_id(rng)
            body_items.append(f"<p>Voter ID Card: {voter}</p>")
            expected.append({"page": page_filename, "type": "voter_id", "value": voter, "location": "p", "category": "positive"})

        # 10. DL
        if rng.random() > 0.6:
            dl = generate_dl(rng)
            body_items.append(f"<p>Driving Licence: {dl}</p>")
            expected.append({"page": page_filename, "type": "driving_licence", "value": dl, "location": "p", "category": "positive"})

        # 11. Plate
        if rng.random() > 0.6:
            plate = generate_plate(rng)
            body_items.append(f"<p>Vehicle Plate: {plate}</p>")
            expected.append({"page": page_filename, "type": "plate", "value": plate, "location": "p", "category": "positive"})

    # HARD NEGATIVES (in both positive and negative pages)
    # A. Order ID
    order_id = f"ORD-{rng.randint(10000000, 99999999)}"
    body_items.append(f"<p>Order Reference: <span>{order_id}</span></p>")

    # B. Timestamps
    iso_time = f"2026-09-28T{rng.randint(10, 23)}:{rng.randint(10, 59)}:{rng.randint(10, 59)}Z"
    body_items.append(f"<p>Updated At: {iso_time}</p>")

    # C. Verhoeff failing 12-digit number
    bad_aadhaar = generate_verhoeff_aadhaar(rng, valid=False)
    bad_aadhaar_spaced = f"{bad_aadhaar[:4]} {bad_aadhaar[4:8]} {bad_aadhaar[8:]}"
    body_items.append(f"<p>Tracking Serial (Not PII): {bad_aadhaar_spaced}</p>")

    # D. Luhn failing 16-digit number
    bad_card = generate_luhn_card(rng, valid=False)
    bad_card_spaced = f"{bad_card[:4]} {bad_card[4:8]} {bad_card[8:12]} {bad_card[12:]}"
    body_items.append(f"<p>Invoice Batch Number: {bad_card_spaced}</p>")

    # E. ISBN
    isbn = f"978-3-16-{rng.randint(100000, 999999)}-0"
    body_items.append(f"<p>Book Catalog ISBN: {isbn}</p>")

    # F. PAN lookalike in code sample
    code_pan = f"0x{generate_pan(rng)}"
    body_items.append(f"<pre><code>const CONFIG_{code_pan} = true;</code></pre>")

    # G. Form control attributes
    body_items.append('<label>Search: <input type="text" name="query" title="Search documentation"></label>')

    rng.shuffle(body_items)

    html = f"""<!doctype html>
<!-- SYNTHETIC TEST DATA: All identities, numbers, and documents are artificially generated and fictional. -->
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Synthetic Test Page {page_id}</title>
</head>
<body style="font:14px system-ui;max-width:600px;margin:30px auto;line-height:1.6">
  <h2>SYNTHETIC DEMO PAGE #{page_id}</h2>
  <div class="content">
    {"".join(body_items)}
  </div>
</body>
</html>
"""
    return html, expected

def generate_all():
    DEV_DIR.mkdir(parents=True, exist_ok=True)
    HELD_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Dev set: 60 pages with fixed seed 42
    print("Generating 60 Dev Pages (seed=42)...")
    dev_rng = random.Random(42)
    dev_fake = Faker("en_IN")
    dev_fake.seed_instance(42)
    dev_expected = []

    for i in range(1, 61):
        html, exp = generate_page(i, dev_rng, dev_fake)
        file_path = DEV_DIR / f"page_{i:03d}.html"
        file_path.write_text(html, encoding="utf-8")
        dev_expected.extend(exp)

    (DEV_DIR / "expected.json").write_text(json.dumps(dev_expected, indent=2), encoding="utf-8")
    print(f"  Saved 60 dev pages to {DEV_DIR}")
    print(f"  Saved {len(dev_expected)} expected items to {DEV_DIR / 'expected.json'}")

    # Held-out set: 40 pages with fixed seed 1337 (strictly isolated!)
    print("Generating 40 Held-Out Pages (seed=1337)...")
    held_rng = random.Random(1337)
    held_fake = Faker("en_IN")
    held_fake.seed_instance(1337)
    held_expected = []

    for i in range(1, 41):
        html, exp = generate_page(i, held_rng, held_fake)
        file_path = HELD_OUT_DIR / f"page_{i:03d}.html"
        file_path.write_text(html, encoding="utf-8")
        held_expected.extend(exp)

    (HELD_OUT_DIR / "expected.json").write_text(json.dumps(held_expected, indent=2), encoding="utf-8")
    print(f"  Saved 40 held-out pages to {HELD_OUT_DIR}")
    print(f"  Saved {len(held_expected)} expected items to {HELD_OUT_DIR / 'expected.json'}")

if __name__ == "__main__":
    generate_all()
