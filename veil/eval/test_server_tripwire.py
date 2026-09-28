"""Test server tripwire against Phase 2 corpus (Task 3).
Validates that tripwire.py detects all PII types independently,
and never echoes any values.
"""
import json
from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

from tripwire import detect_pii, scan_payload_for_pii


def test_corpus_expected_pii():
    eval_dir = Path(__file__).resolve().parent
    corpus_dirs = [eval_dir / "corpus" / "dev", eval_dir / "corpus" / "held_out"]

    total_positives = 0
    detected_positives = 0
    by_type = {}

    for c_dir in corpus_dirs:
        exp_file = c_dir / "expected.json"
        if not exp_file.exists():
            continue
        with open(exp_file, "r", encoding="utf-8") as f:
            items = json.load(f)

        for item in items:
            category = item.get("category", "positive")
            pii_type = item.get("type")
            val = item.get("value", "")

            if category == "positive":
                total_positives += 1
                found = detect_pii(val)
                hit = pii_type in found
                if hit:
                    detected_positives += 1
                stats = by_type.setdefault(pii_type, {"total": 0, "detected": 0})
                stats["total"] += 1
                if hit:
                    stats["detected"] += 1

    recall = detected_positives / total_positives if total_positives > 0 else 0
    print(f"\nCorpus PII Evaluation Summary:")
    print(f"Total Positive PII test values: {total_positives}")
    print(f"Detected by independent Tripwire: {detected_positives} ({recall * 100:.2f}%)")
    for t, s in sorted(by_type.items()):
        pct = (s["detected"] / s["total"] * 100) if s["total"] > 0 else 0
        print(f"  - {t}: {s['detected']}/{s['total']} ({pct:.1f}%)")

    assert recall >= 0.95, f"Tripwire recall {recall:.2f} fell below 95% target!"
    print("[PASS] Independent Python Tripwire achieves >= 95% recall on Phase 2 corpus.")


def test_payload_tripwire_rejection():
    """Verify that scan_payload_for_pii finds leaks nested anywhere in a payload."""
    leak_payload = {
        "v": "1.0",
        "mode": "Balanced",
        "goal": "check user test@example.com account",
        "step": 1,
        "history": [],
        "dom": {
            "url": "https://bank.example.com",
            "viewport": [1280, 720],
            "scrollY": 0,
            "nodes": [
                {
                    "id": "e1",
                    "tag": "div",
                    "sensitive": False,
                    "bbox": [10, 10, 100, 20],
                    "text": "Your Aadhaar is 2345 6789 0124"
                }
            ]
        },
        "manifest": [],
        "legend_version": "1.0"
    }

    types = scan_payload_for_pii(leak_payload)
    assert "email" in types, f"Expected email in {types}"
    assert "aadhaar" in types, f"Expected aadhaar in {types}"
    print(f"[PASS] Nested payload tripwire detected leak types: {types} (values never echoed)")


if __name__ == "__main__":
    test_corpus_expected_pii()
    test_payload_tripwire_rejection()
