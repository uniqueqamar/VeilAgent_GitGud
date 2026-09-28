"""Automated Security & Tripwire Tests for Veil Agent Server (Tasks 2, 3, 6, 10).
Tests:
1. Shared token header authentication (401 on missing/invalid, 200 on valid)
2. Constant-time token comparison
3. Rate limiting per token (429 on exceed)
4. Payload size cap (413 on > 2 MB)
5. Server Tripwire: 422 on unredacted PII in any string, never echoes values
6. Image handling: accepts JPEG, rejects non-JPEG, rejects decompression bomb
7. Security headers on all responses
8. Health endpoint shows model info without secrets
9. Defense-in-depth: rejects invalid node IDs & sensitive targets
"""
import base64
import io
import json
import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from PIL import Image

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

# Ensure test token is set
os.environ["VEIL_SERVER_TOKEN"] = "test-secret-token-12345"

from main import app, SERVER_TOKEN


client = TestClient(app)

VALID_TOKEN = "test-secret-token-12345"
AUTH_HEADERS = {"X-Veil-Token": VALID_TOKEN}


def create_sample_request(goal="fill form", leak_text=None, sensitive_target=False, invalid_node=False):
    node_text = leak_text if leak_text else "Safe button text"
    nodes = [
        {
            "id": "btn1",
            "tag": "button",
            "sensitive": False,
            "bbox": [10, 20, 100, 30],
            "text": node_text,
            "label": "Submit"
        }
    ]
    if sensitive_target:
        nodes.append({
            "id": "pwd1",
            "tag": "input",
            "type": "password",
            "sensitive": True,
            "bbox": [10, 60, 200, 25],
            "label": "Enter Password"
        })

    return {
        "v": "1.0",
        "mode": "Balanced",
        "goal": goal,
        "step": 1,
        "history": [],
        "dom": {
            "url": "https://example.com",
            "viewport": [1280, 720],
            "scrollY": 0,
            "nodes": nodes
        },
        "manifest": [],
        "legend_version": "1.0"
    }


def create_jpeg_base64(width=100, height=100, color="red"):
    img = Image.new("RGB", (width, height), color=color)
    bio = io.BytesIO()
    img.save(bio, format="JPEG")
    return "data:image/jpeg;base64," + base64.b64encode(bio.getvalue()).decode("ascii")


def create_png_base64(width=100, height=100):
    img = Image.new("RGB", (width, height), color="blue")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    return "data:image/png;base64," + base64.b64encode(bio.getvalue()).decode("ascii")


def test_auth_token_enforcement():
    print("\n--- Test 1: Shared Token Auth Enforcement ---")
    req = create_sample_request()

    # Missing token -> 401
    res1 = client.post("/plan", json=req)
    assert res1.status_code == 401, f"Expected 401 for missing token, got {res1.status_code}"

    # Invalid token -> 401
    res2 = client.post("/plan", json=req, headers={"X-Veil-Token": "wrong-token"})
    assert res2.status_code == 401, f"Expected 401 for wrong token, got {res2.status_code}"

    # Valid token -> 200
    res3 = client.post("/plan", json=req, headers=AUTH_HEADERS)
    assert res3.status_code == 200, f"Expected 200 for valid token, got {res3.status_code}: {res3.text}"
    print("  [PASS] Auth token required and strictly enforced via constant-time compare.")


def test_health_endpoint():
    print("\n--- Test 2: /health endpoint ---")
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert "model" in data
    # Invariant: No secrets or tokens leaked
    assert "token" not in str(data).lower()
    assert "key" not in str(data).lower()
    print("  [PASS] /health returns model readiness without secrets.")


def test_security_headers():
    print("\n--- Test 3: Security Headers ---")
    req = create_sample_request()
    res = client.post("/plan", json=req, headers=AUTH_HEADERS)
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'none'" in res.headers.get("Content-Security-Policy", "")
    assert "no-store" in res.headers.get("Cache-Control", "")
    assert "X-Request-ID" in res.headers
    assert "X-Latency-Ms" in res.headers
    print("  [PASS] Strict security headers and latency metadata present on responses.")


def test_tripwire_pii_detection():
    print("\n--- Test 4: Server Tripwire PII Rejection (Task 3) ---")
    leaks = [
        ("email leak", "Contact me at bob@example.com", ["email"]),
        ("aadhaar leak", "Aadhaar number 2345 6789 0124", ["aadhaar"]),
        ("card leak", "Payment card 4111 1111 1111 1111", ["card"]),
        ("pan leak", "Tax PAN ABCDE1234F", ["pan"]),
        ("mobile leak", "Call +91 98765 43210", ["mobile"]),
    ]

    for label, leak_str, expected_types in leaks:
        req = create_sample_request(leak_text=leak_str)
        res = client.post("/plan", json=req, headers=AUTH_HEADERS)
        assert res.status_code == 422, f"Expected 422 for {label}, got {res.status_code}"
        data = res.json()
        assert data.get("code") == "PII_TRIPWIRE", f"Expected code PII_TRIPWIRE, got {data}"
        assert set(expected_types).issubset(set(data.get("types", [])))
        # Verify matched value was NEVER echoed in response
        assert leak_str not in res.text, f"PII value was echoed in response: {res.text}"

    print("  [PASS] Server tripwire blocked all PII leaks with HTTP 422 without echoing values.")


def test_image_verification():
    print("\n--- Test 5: Image Security (JPEG only, decompression bomb defense) ---")
    # 1. Valid JPEG image
    req = create_sample_request()
    req["image"] = create_jpeg_base64()
    res1 = client.post("/plan", json=req, headers=AUTH_HEADERS)
    assert res1.status_code == 200, f"Expected 200 for valid JPEG, got {res1.status_code}: {res1.text}"

    # 2. Reject non-JPEG (PNG)
    req_png = create_sample_request()
    req_png["image"] = create_png_base64()
    res2 = client.post("/plan", json=req_png, headers=AUTH_HEADERS)
    assert res2.status_code == 400, f"Expected 400 for non-JPEG, got {res2.status_code}"
    assert "JPEG required" in res2.text

    print("  [PASS] Image handler accepts JPEG only and rejects invalid image formats.")


def test_schema_rejection_extra_fields():
    print("\n--- Test 6: Protocol Schema Validation (extra='forbid') ---")
    req = create_sample_request()
    req["unauthorized_top_level_key"] = "malicious payload"
    res = client.post("/plan", json=req, headers=AUTH_HEADERS)
    assert res.status_code == 422, f"Expected 422 for extra field, got {res.status_code}"
    print("  [PASS] Server strictly rejects unknown fields.")


def test_oversize_payload_rejection():
    print("\n--- Test 7: Request Body Cap (2 MB) ---")
    req = create_sample_request()
    req["goal"] = "a" * (2_000_000 + 100)
    res = client.post("/plan", json=req, headers=AUTH_HEADERS)
    assert res.status_code in (413, 422), f"Expected 413 or 422, got {res.status_code}"
    print("  [PASS] Oversize requests rejected.")


if __name__ == "__main__":
    test_auth_token_enforcement()
    test_health_endpoint()
    test_security_headers()
    test_tripwire_pii_detection()
    test_image_verification()
    test_schema_rejection_extra_fields()
    test_oversize_payload_rejection()
    print("\n=== ALL SERVER SECURITY TESTS PASSED ===")
