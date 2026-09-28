"""
Evaluation Metrics for Veil Agent PII Detection (Task 6).
Evaluates dev and held-out sets separately.
Matches findings against expected.json by type and value overlap.
Computes per-type Precision, Recall, F1, and False Positives per hard-negative category.
Saves results into eval/results/ with timestamp.
"""
import json
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BASE_DIR / "corpus"
RESULTS_DIR = BASE_DIR / "results"

PII_TYPES = [
    "email", "mobile", "aadhaar", "pan", "ifsc", "upi",
    "passport", "voter_id", "driving_licence", "plate", "card"
]

HARD_NEGATIVE_PATTERNS = {
    "order_id": re.compile(r"\b(ORD-\d+|OD\d+|PO#\d+)\b", re.I),
    "timestamp": re.compile(r"\b(\d{4}-\d{2}-\d{2}T|\d{10}\b|\d{4}/\d{2}/\d{2})", re.I),
    "verhoeff_fail": re.compile(r"\bTracking Serial\b", re.I),
    "luhn_fail": re.compile(r"\bInvoice Batch Number\b", re.I),
    "isbn": re.compile(r"\b978-\d|\bISBN\b", re.I),
    "pan_lookalike": re.compile(r"\b(CONFIG_0x|0x[A-Z0-9]+)\b", re.I),
}

DEVANAGARI_MAP = {
    '०': '0', '१': '1', '२': '2', '३': '3', '४': '4',
    '५': '5', '६': '6', '७': '7', '८': '8', '९': '9'
}

def normalize_digits(s: str) -> str:
    for dev, asc in DEVANAGARI_MAP.items():
        s = s.replace(dev, asc)
    return re.sub(r"[\s\-\+\(\)\.]", "", s).lower()

def is_value_match(pred_val: str, exp_val: str, pii_type: str) -> bool:
    pv = pred_val.strip().lower()
    ev = exp_val.strip().lower()
    if pv == ev:
        return True
    if pv in ev or ev in pv:
        return True

    # Digit-based normalization for phone, aadhaar, card
    if pii_type in ("mobile", "aadhaar", "card", "plate", "driving_licence"):
        p_norm = normalize_digits(pv)
        e_norm = normalize_digits(ev)
        if p_norm == e_norm or p_norm.endswith(e_norm) or e_norm.endswith(p_norm):
            return True

    return False

def evaluate_set(set_name: str, set_dir: Path):
    expected_file = set_dir / "expected.json"
    findings_file = set_dir / "findings.json"

    if not expected_file.exists() or not findings_file.exists():
        print(f"Missing expected or findings in {set_dir}")
        return None

    expected = json.loads(expected_file.read_text(encoding="utf-8"))
    findings = json.loads(findings_file.read_text(encoding="utf-8"))

    # Group expected by page
    expected_by_page = {}
    for exp in expected:
        expected_by_page.setdefault(exp["page"], []).append(exp)

    # Group findings by page
    findings_by_page = {}
    for f in findings:
        findings_by_page.setdefault(f["page"], []).append(f)

    # Metrics per type
    tp = {t: 0 for t in PII_TYPES}
    fp = {t: 0 for t in PII_TYPES}
    fn = {t: 0 for t in PII_TYPES}

    unmatched_findings = []
    unmatched_expected = []

    all_pages = set(expected_by_page.keys()) | set(findings_by_page.keys())

    for page in all_pages:
        page_exp = expected_by_page.get(page, [])
        page_find = findings_by_page.get(page, [])

        matched_exp_indices = set()
        matched_find_indices = set()

        # Match findings to expected
        for fi, f in enumerate(page_find):
            ftype = f["type"]
            fval = f["value"]
            matched = False
            for ei, exp in enumerate(page_exp):
                if ei in matched_exp_indices:
                    continue
                if exp["type"] == ftype and is_value_match(fval, exp["value"], ftype):
                    matched = True
                    matched_exp_indices.add(ei)
                    matched_find_indices.add(fi)
                    if ftype in tp:
                        tp[ftype] += 1
                    break

            if not matched:
                if ftype in fp:
                    fp[ftype] += 1
                unmatched_findings.append(f)

        for ei, exp in enumerate(page_exp):
            if ei not in matched_exp_indices:
                etype = exp["type"]
                if etype in fn:
                    fn[etype] += 1
                unmatched_expected.append(exp)

    # False positives on hard negative categories
    hard_neg_fp = {cat: 0 for cat in HARD_NEGATIVE_PATTERNS}
    for uf in unmatched_findings:
        u_val = uf["value"]
        for cat, pat in HARD_NEGATIVE_PATTERNS.items():
            if pat.search(u_val):
                hard_neg_fp[cat] += 1

    # Compute precision, recall, f1
    per_type_metrics = {}
    total_tp = sum(tp.values())
    total_fp = sum(fp.values())
    total_fn = sum(fn.values())

    for t in PII_TYPES:
        c_tp = tp[t]
        c_fp = fp[t]
        c_fn = fn[t]
        prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
        rec = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        per_type_metrics[t] = {
            "TP": c_tp, "FP": c_fp, "FN": c_fn,
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1": round(f1, 4)
        }

    macro_f1 = sum(m["F1"] for m in per_type_metrics.values()) / len(PII_TYPES)
    micro_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    micro_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    micro_f1 = (2 * micro_prec * micro_rec) / (micro_prec + micro_rec) if (micro_prec + micro_rec) > 0 else 0.0

    return {
        "set_name": set_name,
        "total_expected": len(expected),
        "total_findings": len(findings),
        "per_type_metrics": per_type_metrics,
        "macro_f1": round(macro_f1, 4),
        "micro_precision": round(micro_prec, 4),
        "micro_recall": round(micro_rec, 4),
        "micro_f1": round(micro_f1, 4),
        "hard_negative_false_positives": hard_neg_fp,
        "unmatched_findings_sample": unmatched_findings[:10],
        "unmatched_expected_sample": unmatched_expected[:10]
    }

def print_and_save_report():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    dev_results = evaluate_set("Dev Set (60 pages)", CORPUS_DIR / "dev")
    held_results = evaluate_set("Held-Out Set (40 pages)", CORPUS_DIR / "held_out")

    report_lines = []
    def log(msg=""):
        print(msg)
        report_lines.append(msg)

    log("=" * 80)
    log(f"VEIL AGENT PII DETECTION EVALUATION REPORT - {today}")
    log("=" * 80)

    for res in [dev_results, held_results]:
        if not res:
            continue
        log(f"\n### {res['set_name']} Results")
        log(f"Total Expected Targets: {res['total_expected']} | Total System Findings: {res['total_findings']}")
        log(f"Overall Micro F1: {res['micro_f1']} (Precision: {res['micro_precision']}, Recall: {res['micro_recall']}) | Macro F1: {res['macro_f1']}")
        log("-" * 80)
        log(f"{'PII Type':<18} {'TP':<6} {'FP':<6} {'FN':<6} {'Precision':<12} {'Recall':<12} {'F1-Score':<10}")
        log("-" * 80)
        for t, m in res["per_type_metrics"].items():
            log(f"{t:<18} {m['TP']:<6} {m['FP']:<6} {m['FN']:<6} {m['Precision']:<12.4f} {m['Recall']:<12.4f} {m['F1']:<10.4f}")
        log("-" * 80)

        log("\nHard-Negative False Positive Counts:")
        for cat, count in res["hard_negative_false_positives"].items():
            status = "PASS (0 FP)" if count == 0 else f"FP Detected: {count}"
            log(f"  - {cat:<20}: {count:<4} [{status}]")

        log("\nFailure Cases Observed (First 5 Unmatched Findings / FPs):")
        if res["unmatched_findings_sample"]:
            for uf in res["unmatched_findings_sample"][:5]:
                log(f"  * FP on {uf['page']}: type={uf['type']} val='{uf['value']}' loc={uf.get('location')}")
        else:
            log("  (None - 0 false positives)")

        log("\nFailure Cases Observed (First 5 Missed Targets / FNs):")
        if res["unmatched_expected_sample"]:
            for ue in res["unmatched_expected_sample"][:5]:
                log(f"  * FN on {ue['page']}: type={ue['type']} val='{ue['value']}' loc={ue.get('location')}")
        else:
            log("  (None - 0 missed targets)")

    # Save outputs
    json_path = RESULTS_DIR / f"results_{today}.json"
    txt_path = RESULTS_DIR / f"results_{today}.txt"

    full_data = {"date": today, "dev": dev_results, "held_out": held_results}
    json_path.write_text(json.dumps(full_data, indent=2), encoding="utf-8")
    txt_path.write_text("\n".join(report_lines), encoding="utf-8")

    log("\n" + "=" * 80)
    log(f"Saved evaluation report to {txt_path}")
    log(f"Saved JSON metrics to {json_path}")
    log("=" * 80)

if __name__ == "__main__":
    print_and_save_report()
