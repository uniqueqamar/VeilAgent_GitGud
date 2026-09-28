"""Independent Python PII Detector & Server Tripwire (Task 3).
Ported independently to Python with own Verhoeff and Luhn checksum algorithms.
Never echoes or logs matched PII values.
Returns HTTP 422 with {"code": "PII_TRIPWIRE", "types": [...]} on any detection.
"""
import re
import time
from typing import Any, List, Set

# Verhoeff algorithm tables (independent implementation)
_VERHOEFF_D = [
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

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff(num_str: str) -> bool:
    """Validate 12-digit number against Verhoeff checksum."""
    if not num_str or not num_str.isdigit():
        return False
    c = 0
    length = len(num_str)
    for i in range(length):
        digit = ord(num_str[length - 1 - i]) - 48
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


def validate_luhn(num_str: str) -> bool:
    """Validate 13-19 digit card number against Luhn checksum."""
    if not num_str or not num_str.isdigit():
        return False
    total = 0
    alternate = False
    for i in range(len(num_str) - 1, -1, -1):
        digit = ord(num_str[i]) - 48
        n = digit
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0


def normalize_devanagari(text: str) -> str:
    """Normalize Devanagari numerals (०-९) to ASCII 0-9."""
    chars = []
    for ch in text:
        code = ord(ch)
        if 0x0966 <= code <= 0x096F:
            chars.append(chr(code - 0x0966 + 48))
        else:
            chars.append(ch)
    return "".join(chars)


INDIAN_STATE_CODES = {
    "AN", "AP", "AR", "AS", "BR", "CH", "CG", "DD", "DL", "DN",
    "GA", "GJ", "HR", "HP", "JH", "JK", "KA", "KL", "LA", "LD",
    "MH", "ML", "MN", "MP", "MZ", "NL", "OD", "OR", "PB", "PY",
    "RJ", "SK", "TN", "TR", "TS", "UA", "UK", "UP", "WB"
}

COMMON_UPI_PROVIDERS = {
    "upi", "okhdfcbank", "oksbi", "okaxis", "okicici", "paytm",
    "ybl", "ibl", "axl", "postbank", "barodampay", "apl", "federal",
    "indus", "kotak", "idfcbank", "aubank", "rbl", "pingpay"
}

CONTEXT_KEYWORDS = {
    "aadhaar": ["aadhaar", "aadhar", "uidai", "uid", "आधार"],
    "pan": ["pan", "incometax", "nsdl", "uti", "tax id", "पैन"],
    "card": ["card", "visa", "mastercard", "amex", "rupay", "cvv", "cvc", "credit", "debit", "कार्ड"],
    "mobile": ["mobile", "phone", "cell", "tel", "whatsapp", "call", "contact", "फ़ोन", "मोबाइल"],
    "email": ["email", "e-mail", "mail", "ईमेल"],
    "ifsc": ["ifsc", "neft", "rtgs", "imps", "bank", "branch", "बैंक"],
    "upi": ["upi", "vpa", "bhim", "pay"],
    "passport": ["passport", "travel doc", "visa", "पासपोर्ट"],
    "voter_id": ["voter", "epic", "election", "मतदाता"],
    "driving_licence": ["dl", "driving", "licence", "license", "rto", "ड्राइविंग"],
    "plate": ["vehicle", "registration", "car", "bike", "motor", "rc", "plate", "rto", "गाड़ी"]
}


def _has_context_near(text: str, start: int, end: int, pii_type: str, window_size: int = 60) -> bool:
    keywords = CONTEXT_KEYWORDS.get(pii_type)
    if not keywords:
        return False
    lower = text.lower()
    sub_start = max(0, start - window_size)
    sub_end = min(len(lower), end + window_size)
    window_text = lower[sub_start:sub_end]
    return any(kw in window_text for kw in keywords)


# Compiled regular expressions for fast scanning
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,250}\.[A-Za-z]{2,12}\b")
RE_UPI = re.compile(r"\b[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z0-9]{2,30}\b")
RE_MOBILE = re.compile(r"(?:\+?91[\s-]?)?(?:0[\s-]?)?[6-9](?:[\s-]?\d){9}\b")
RE_AADHAAR = re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b")
RE_CARD = re.compile(r"\b(?:\d[\s-]?){13,19}\b")
RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
RE_PASSPORT = re.compile(r"\b[A-PR-WYZa-pr-wyz][1-9][0-9]{6}\b")
RE_VOTER = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")
RE_DL = re.compile(r"\b([A-Z]{2})[\s-]?(0[1-9]|[1-9][0-9])[\s-]?(19\d\d|20\d\d)[\s-]?(\d{7})\b")
RE_PLATE = re.compile(r"\b(?:([A-Z]{2})[\s-]?(\d{1,2})[\s-]?([A-Z]{1,3})[\s-]?(\d{4})|(\d{2})[\s-]?(BH)[\s-]?(\d{4})[\s-]?([A-Z]{1,2}))\b", re.IGNORECASE)


def detect_pii(raw_text: str) -> List[str]:
    """Detect unredacted PII in raw text. Returns list of detected PII types only (NO values)."""
    if not raw_text or not isinstance(raw_text, str):
        return []

    # ReDoS safety: Cap text at 5,000 characters
    text = raw_text[:5000] if len(raw_text) > 5000 else raw_text
    norm_text = normalize_devanagari(text)
    types_found: Set[str] = set()

    # 1. Email
    for m in RE_EMAIL.finditer(norm_text):
        types_found.add("email")
        break

    # 2. UPI
    for m in RE_UPI.finditer(norm_text):
        val = m.group(0)
        parts = val.split("@")
        if len(parts) == 2:
            provider = parts[1].lower()
            has_dot = "." in provider
            is_known = provider in COMMON_UPI_PROVIDERS
            has_ctx = _has_context_near(norm_text, m.start(), m.end(), "upi")
            if is_known or (not has_dot and has_ctx) or (not has_dot and bool(re.search(r"upi|bank|pay|ok", provider))):
                types_found.add("upi")
                break

    # 3. Mobile
    for m in RE_MOBILE.finditer(norm_text):
        if m.start() > 0 and norm_text[m.start() - 1].isdigit():
            continue
        digits = re.sub(r"\D", "", m.group(0))
        is_mobile = (
            (len(digits) == 10 and digits[0] in "6789")
            or (len(digits) == 11 and digits.startswith("0") and digits[1] in "6789")
            or (len(digits) == 12 and digits.startswith("91") and digits[2] in "6789")
        )
        if is_mobile:
            types_found.add("mobile")
            break

    # 4. Aadhaar (12 digits, first 2-9, Verhoeff checksum)
    for m in RE_AADHAAR.finditer(norm_text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) == 12:
            if len(set(digits)) == 1:
                continue
            if validate_verhoeff(digits):
                types_found.add("aadhaar")
                break

    # 5. Card (13-19 digits, Luhn checksum)
    for m in RE_CARD.finditer(norm_text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19:
            if validate_luhn(digits):
                types_found.add("card")
                break

    # 6. PAN
    for m in RE_PAN.finditer(norm_text):
        if m.start() >= 2 and norm_text[m.start() - 2:m.start()].lower() == "0x":
            continue
        val = m.group(0)
        entity = val[3]
        valid_entity = entity in "PCHFATBLJG"
        has_ctx = _has_context_near(norm_text, m.start(), m.end(), "pan")
        if valid_entity or has_ctx:
            types_found.add("pan")
            break

    # 7. IFSC
    for m in RE_IFSC.finditer(norm_text):
        types_found.add("ifsc")
        break

    # 8. Passport
    for m in RE_PASSPORT.finditer(norm_text):
        types_found.add("passport")
        break

    # 9. Voter ID
    for m in RE_VOTER.finditer(norm_text):
        types_found.add("voter_id")
        break

    # 10. Driving Licence
    for m in RE_DL.finditer(norm_text):
        state = m.group(1)
        if state in INDIAN_STATE_CODES:
            types_found.add("driving_licence")
            break

    # 11. Vehicle Plate
    for m in RE_PLATE.finditer(norm_text):
        state = (m.group(1) or "").upper()
        is_bh = bool(m.group(6))
        if state in INDIAN_STATE_CODES or is_bh:
            types_found.add("plate")
            break

    return sorted(list(types_found))


def scan_payload_for_pii(data: Any, path: str = "") -> List[str]:
    """Recursively scan an entire request object for any unredacted PII string.
    Skips the raw image payload string itself (images are scanned via vision, not text regex).
    Returns list of distinct PII types found, NEVER echoing values.
    """
    detected_types: Set[str] = set()

    if isinstance(data, str):
        # Skip base64 image data payload if path indicates image/screenshot
        if "image" in path or "screenshot" in path:
            return []
        found = detect_pii(data)
        for t in found:
            detected_types.add(t)
    elif isinstance(data, dict):
        for k, v in data.items():
            subpath = f"{path}.{k}" if path else k
            if k in ("image", "screenshot"):
                continue
            sub_types = scan_payload_for_pii(v, subpath)
            for t in sub_types:
                detected_types.add(t)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            subpath = f"{path}[{idx}]"
            sub_types = scan_payload_for_pii(item, subpath)
            for t in sub_types:
                detected_types.add(t)

    return sorted(list(detected_types))
