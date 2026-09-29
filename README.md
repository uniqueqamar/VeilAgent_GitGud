# Veil Agent

> **Zero PII Leakage • On-Device Visual Redaction • Zero-Trust Server Architecture**

Veil Agent is a privacy-preserving browser automation system that allows Large Vision-Language Models (VLMs) and AI planners to perform complex web automation tasks without ever seeing sensitive personal information (PII).

---

## Key Highlights

- **Local-First Vault (`WebCrypto AES-GCM`)**: Real credentials, names, emails, cards, and national IDs reside strictly in the browser. They are resolved into input fields in volatile memory immediately at execution time.
- **On-Device Visual Redactor**: Screenshots are captured and redacted entirely in-memory using an `OffscreenCanvas`. Sensitive form inputs, faces (`UltraFace`), and media are replaced with solid black boxes (`#000000`) before transmission.
- **Fail-Closed Privacy Gatekeeper**: The client-side gatekeeper ([`veil/extension/privacy/gate.js`](file:///d:/downloads/Downloads/veil-skeleton/veil/extension/privacy/gate.js)) is the only module permitted to make network requests. It validates schemas, audits redaction coverage, and terminates the session if unredacted data is detected.
- **Dual Zero-Trust Boundary**: An independent Python PII Tripwire ([`veil/server/tripwire.py`](file:///d:/downloads/Downloads/veil-skeleton/veil/server/tripwire.py)) on the server scans every incoming string with Luhn, Verhoeff, and pattern algorithms, returning HTTP 422 if an anomaly is found.
- **Operating Modes**:
  - **Strict**: Tokenized structural DOM only (zero screenshots transmitted).
  - **Balanced**: Tokenized DOM + on-device redacted screenshots.
  - **Open**: Full-fidelity DOM + high-resolution redacted screenshots for visually dense pages.

---

## Architecture & Execution Flow

```text
Browser Page ──> DOM Capture & PII Tokenization ([EMAIL_1], [PHONE_1])
                      │
                      ▼
               Visual Redactor (Solid black boxes over faces, media & sensitive fields)
                      │
                      ▼
               Privacy Gate (Schema validation & redaction coverage verification)
                      │  POST /plan (Redacted context + tokens only)
                      ▼
               Server Planner (Qwen2.5-VL / Deterministic Planner + PII Tripwire)
                      │  Returns Action (e.g. type f0:e1 {{EMAIL}})
                      ▼
               Local Vault Resolution (Resolves token/placeholder inside browser)
                      │
                      ▼
               Safe Execution (Coordinates, boundaries, & consent verified)
```

---

## Quickstart Guide

### 1. Prerequisites
- **Node.js** 18+
- **Python** 3.10+
- **Google Chrome**, **Brave**, or **Mozilla Firefox**

### 2. Start the Backend Server
```bash
cd veil/server

# Install dependencies
pip install -r requirements.txt

# (Optional) Copy template environment configuration
cp .env.example .env

# Launch the FastAPI planning server on 127.0.0.1:8000
python main.py
```
*The server will start at `http://127.0.0.1:8000` with the shared secret token `veil-shared-secret-token`.*

### 3. Load the Browser Extension
1. Open your browser and navigate to `chrome://extensions/` (or `about:debugging` in Firefox).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the [`veil/extension`](file:///d:/downloads/Downloads/veil-skeleton/veil/extension) directory.
4. Pin the **Veil Agent** icon to your toolbar.

### 4. Run an Automation Session
1. Open any web form or target page (e.g. [`veil/eval/synthetic_pages/kyc.html`](file:///d:/downloads/Downloads/veil-skeleton/veil/eval/synthetic_pages/kyc.html)).
2. Click the Veil Agent extension icon to open the popup.
3. Select your desired mode (**Balanced** or **Strict**).
4. Enter your goal (e.g., `"Complete the KYC verification form"`) and click **Run Agent**.
5. Inspect the live audit trail and click **What Server Sees** to verify that all sensitive data is masked.

---

## Configuration

| Environment Variable | Default | Purpose |
|:---|:---|:---|
| `VEIL_SERVER_TOKEN` | `veil-shared-secret-token` | Shared authentication secret sent via `X-Veil-Token` header. |
| `VEIL_PLANNER_BACKEND` | `deterministic` | Planner engine: `deterministic`, `local_vlm`, or `cloud_vlm`. |
| `LOCAL_VLM_URL` | `http://127.0.0.1:11434/v1/chat/completions` | Local Ollama/VLLM endpoint for Qwen2.5-VL. |
| `LOCAL_VLM_MODEL` | `qwen2.5-vl:7b` | Model name for local vision-language inference. |
| `VEIL_ALLOW_CLOUD` | `0` | Set to `1` only if cloud inference fallback is explicitly authorized. |

*In the browser extension, the Server URL and Shared Secret Token can also be configured directly via the **Backend Connection** panel in the popup UI.*

---

## Evaluation & Testing

Run the full evaluation and security test suites from the repository root:

```bash
# Run unit, integration, and security evaluation suites
node --test veil/eval/phase3_redactor.test.js veil/eval/phase3_unit.test.js veil/eval/phase3_gate_leak.test.js veil/eval/phase4_vision.test.js veil/eval/phase6_schema_fuzz.test.js veil/eval/phase8_form_filling.test.js veil/eval/phase9_production.test.js

# Run server security, tripwire & authentication tests
python veil/eval/test_server_security.py
```

### Build Production Packages
To generate audited, production-ready extension zips for Chrome and Firefox:
```bash
python veil/scripts/build_release.py
```
Output packages will be validated and placed into `veil/dist/`:
- `veil/dist/veil-chrome.zip`
- `veil/dist/veil-firefox.zip`

---

## Repository Structure

```text
veil/
├── extension/             # Browser extension (MV3)
│   ├── background/        # Background orchestrator & event loops
│   ├── content/           # DOM capture & action executor scripts
│   ├── privacy/           # Gatekeeper, Redactor, Vault & Domain Guard
│   ├── workers/           # PII detector & local field matcher
│   ├── ui/                # Extension popup UI and inspection views
│   └── manifest.json      # Chromium & Firefox MV3 manifest
├── server/                # Hardened FastAPI planning server
│   ├── main.py            # API endpoints & security middleware
│   ├── planner.py         # Deterministic & VLM planning backends
│   ├── tripwire.py        # Independent server-side PII detector
│   └── schema.py          # Strict Pydantic protocol request/response models
├── eval/                  # Test suites, benchmarks, and synthetic pages
├── scripts/               # Release build and packaging scripts
└── shared/                # Canonical JSON Schema definitions
```

---

## Core Security Invariants

1. **Zero Raw PII Egress**: Real identity values never leave the browser client.
2. **Single Network Egress**: Only [`privacy/gate.js`](file:///d:/downloads/Downloads/veil-skeleton/veil/extension/privacy/gate.js) is permitted to make outbound HTTP requests.
3. **In-Memory Volatility**: Screen captures and audio buffers are held in volatile memory only and are never written to disk.
4. **Fail-Closed Gatekeeper**: If redaction verification fails or anomalous keys are detected, the gate aborts the session immediately.
5. **No Blind Trust**: Actions received from the server planner are validated for boundary bounds, clickjacking overlays, and sensitive targets before execution.
