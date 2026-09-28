# Veil Agent Phase 4 - Vision Evaluation Report
**Date:** 2026-09-28 20:53:44  
**Evaluation Scope:** 100 Synthetic Pages (60 Dev + 40 Held-Out), 32 ID Variants, 11 Face Portraits, 8 Hard Negatives.

## 1. Face Detection Quality
| Split | Precision | Recall | Mean IoU |
|---|---|---|---|
| **Dev Set (60 pages)** | 47.0% | 87.6% | 0.580 |
| **Held-Out Set (40 pages)** | 48.2% | 88.3% | 0.578 |

### Breakdowns by Group (Held-Out)
- **Small Faces in Groups:** Recall 100.0%
- **Profiles:** Recall 100.0%
- **Masks / Glasses:** Recall 100.0%

## 2. OCR PII Detection Quality
- **English PII Recall:** 100.0%
- **Hindi (Devanagari) PII Recall:** 100.0%

| Document Variant | Word-Level Recall | Status |
|---|---|---|
| Clean | 100.0% | Detected / Redacted |
| Rotated (3.5 deg) | 100.0% | Detected / Redacted |
| Blur | 100.0% | Fail-closed Full Blackout |
| Low Resolution | 100.0% | Fail-closed Full Blackout |
| JPEG Artifacts | 100.0% | Detected / Redacted |
| Dark Mode | 100.0% | Detected / Redacted |
| Small Font | 100.0% | Fail-closed Full Blackout |
| Screen Photo | 100.0% | Fail-closed Full Blackout |

## 3. Redaction Quality (Privacy vs Usability)
- **Coverage (Privacy Guarantee, Target >= 95%):** 100.00%
- **Excess Redacted Area (Usability Cost):** 16.33%
- **IoU vs Ground Truth:** 0.181
- **End-to-End Pixel Leakage Status:** **ZERO LEAKS** (3,015,518 sensitive pixels audited, 0 leaks).

## 4. Latency Benchmark (Per-Step)
- **Capture:** 18.5 ms
- **Vision Detection (WASM SIMD):** 51.24 ms (Face: 8.85 ms, OCR: 42.39 ms)
- **Redaction & Self-Check:** 7.2 ms
- **Network Egress (Gate):** 4.1 ms
- **Action Execution:** 22.0 ms
- **Total Step (Vision ON):** 103.04 ms
- **Total Step (Vision OFF):** 51.8 ms

## 5. Documented Limitations
1. Handwriting: Unconstrained handwriting is out of distribution for DBNet; triggers fail-closed blackout.
2. Stylized/Rotated text > 10 degrees: Text detector axis-aligned bounding boxes fail closed.
3. Blurred / Low-res text: Unclear OCR characters trigger whole-document layout blackout.
4. Faces < 20 px: Below RFB-320 anchor resolution; fail-closed element redaction applies.
5. Cross-origin iframes: Browsers disallow cross-origin canvas pixel reads; elements stay fully solid black.
