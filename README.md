# 🛡️ Veil Agent — On-Device Visual Perception for Privacy-Preserving Browser Agents
### Smart India Hackathon (SIH) • Department of Space / Indian Space Research Organisation (ISRO) • Problem Statement: 26171

> **On-Device Vision Transformer (ViT) • Solid Black Visual Redaction • Client-Side Face & PII Masking • SHA-256 Cryptographic Receipts • Hardened VLM Server • AES-GCM Encrypted Vault**

---

## 📌 Executive Summary

**Veil Agent** bridges the gap between client-side data privacy and cloud/server AI reasoning for browser automation:
1. **Client-Side Visual Perception**: Evaluates screen state using on-device computer vision models (UltraFace for face detection, PaddleOCR for optical character recognition, and YOLOX for UI elements) running via **WebGPU / WebAssembly (ONNX Runtime Web)**.
2. **Visual Privacy-Preserving Filter**: Dynamically detects and redacts sensitive elements directly inside an `OffscreenCanvas`. Human faces are blurred/masked, passwords/sensitive inputs are blacked out, and PII text (Aadhaar with Verhoeff checksum, PAN, phone numbers, emails, credit cards) is solidly masked (`#000000`) before any network request is created.
3. **Tamper-Evident Privacy Gate**: Enforces schema allowlists, payload caps, and generates a chained **SHA-256 cryptographic receipt** for every transmission.
4. **Hardened Server & VLM Planner**: Receives only sanitized visual context and structural DOM. Evaluates actions using a deterministic rules engine (instant, zero downloads required) or pluggable open-weights VLM (Qwen-VL, LLaVA, Ollama) with an independent server-side PII tripwire.
5. **Instant Form Autofill Companion**: Includes a local AES-GCM encrypted vault with intelligent entity matching, sensitive credential skip, and mandatory approval before form submission.

---

## 🏛️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      CLIENT-SIDE BROWSER (Chrome MV3)                  │
│                                                                        │
│  [ Web Page / Form ] ──► [ DOM Capture ] (Structural only, no values)  │
│                               │                                        │
│  [ Viewport Screenshot ] ─────┼──► [ Client Vision: ViT / UltraFace ]  │
│                               ▼                                        │
│                      [ Canvas Redactor ]                               │
│              • Solid black (#000000) 4px expanded                      │
│              • Faces blurred / masked                                  │
│              • Aadhaar (Verhoeff) & PAN redacted                       │
│              • Self-checking pixel sampling verification               │
│                               │                                        │
│                               ▼                                        │
│                      [ Privacy Gate ]                                  │
│              • Single egress point (Invariant 2)                       │
│              • Allowlist schema & payload size cap                     │
│              • SHA-256 chained cryptographic receipts                  │
└───────────────────────────────┬────────────────────────────────────────┘
                                │ Sanitized Screenshot + Structural DOM
                                ▼ (http://127.0.0.1:8000/plan)
┌────────────────────────────────────────────────────────────────────────┐
│                   SERVER-SIDE (FastAPI + Python 3.13)                  │
│                                                                        │
│  [ PII Tripwire ] ──► In-memory Pillow JPEG sanitization               │
│                            │                                           │
│                            ▼                                           │
│  [ Planners ] ──► Deterministic / Local VLM (Ollama) / Cloud VLM       │
│                            │                                           │
│                            ▼                                           │
│              [ Planned Action ] (e.g. {{FULL_NAME}}, click)            │
└────────────────────────────┬───────────────────────────────────────────┘
                             │ Untrusted action
                             ▼
┌────────────────────────────────────────────────────────────────────────┐
│  [ Action Validation ] ──► Local Vault Placeholder Resolution          │
│                               │                                        │
│                               ▼                                        │
│  [ Executor ] ──────────► In-page action + Anti-honeypot guard         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 SIH PS 26171 Evaluation Criteria Alignment

| # | Evaluation Criteria | Weight | Implementation Details |
|---|---------------------|--------|------------------------|
| **1** | **Accuracy of visual context from screen** | **25%** | Client-side **UltraFace**, **PaddleOCR**, and **YOLOX** running via ONNX Runtime Web (`ort.all.min.js`, WASM/WebGPU). Fuses visual bounding boxes with structural DOM elements. |
| **2** | **Recall & precision of sensitive/PII detection** | **20%** | Mathematical **Verhoeff checksum** algorithm for Aadhaar, PAN card regex, phone/email/card detection, and independent server-side **PII Tripwire** returning HTTP 422 on leaks. |
| **3** | **Precision of redaction** | **20%** | Canvas-based solid black (`#000000`) masking with 4px expansion, viewport clipping, pre/post capture sync check (`didBoxesMove`), and self-checking pixel sampling (`verifyBoxBlack`). |
| **4** | **Client-side resource utilization** | **20%** | WebGPU SIMD threaded execution, in-memory volatile perceptual difference hashing (`computeCropDHash`) to avoid redundant inference, and zero disk writes. |
| **5** | **Overall end-to-end latency** | **15%** | Real-time telemetry logging (`_latencyMs`), sub-10ms deterministic planner execution, and strict 15s timeout safeguards. |

---

## 🚀 Quickstart for Evaluators

### Step 1: Start the Local Vision & Privacy Server

Open a terminal in the project directory:

```powershell
# Navigate to the repo
cd d:\downloads\Downloads\veil-skeleton

# Run the FastAPI server
python veil/server/main.py
```

* The server starts at `http://127.0.0.1:8000`.
* Verification: Visit `http://127.0.0.1:8000/health` to confirm `status: ready`.

---

### Step 2: Load the Extension in Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** (top-right corner) to **ON**.
3. Click **Load unpacked** (top-left).
4. Select the directory:
   ```text
   d:\downloads\Downloads\veil-skeleton\veil\extension
   ```
5. Pin **Veil Agent** to your Chrome toolbar.

---

### Step 3: Run the Demonstration Workflows

#### Workflow A: Autonomous Vision AI Agent (Client-Server Pipeline)
1. Open any web form or KYC portal (e.g. `veil/eval/synthetic_pages/kyc.html` or a live form).
2. Click the **Veil Agent** toolbar icon and open the **Vision AI Agent** tab.
3. Check the server pill: shows **🟢 Server: Connected**.
4. Select operating mode:
   * **Balanced**: Runs client-side ViT / face detection + OffscreenCanvas solid black redaction + sends sanitized screenshot to server.
   * **Strict**: Zero screenshots transmitted; pure tokenized structural DOM.
   * **Open**: Full resolution visual context.
5. Click **Start Vision Agent**. Watch real-time latency and telemetry update.
6. Click **🔍 What Server Sees** to open the inspection modal:
   * **Box Overlays**: Color-coded overlay canvas showing detected faces (Red), OCR PII (Orange), DOM PII (Purple), and cleared media (Green dashed).
   * **Redacted Image**: Inspect the actual solid black `#000000` image received by the server.
   * **Original**: Volatile client-side original view.
   * **Manifest**: JSON array of redacted coordinates.
7. Click **🛡️ Export Audit Receipts** to download the chained SHA-256 tamper-evident JSON receipt audit log.

#### Workflow B: Instant On-Device Form Autofill
1. Open a Google Form, signup, or application page.
2. In the popup or via the **draggable in-page floating widget**, click **Auto-Fill Form**.
3. All standard fields fill instantly from your encrypted Vault.
4. Sensitive fields (**Password, Aadhaar, PAN**) are **strictly skipped** and tagged.
5. Review the summary table and click **Approve and Submit** to finalize.

---

## 🧪 Automated Test Suite

Run the test suite using Node.js:

```powershell
# 1. PII Detection Suite (Verhoeff checksum, PAN, ReDoS safety)
node --test veil/eval/pii.test.js

# 2. Privacy Gate & Leaky Payload Tests
node --test veil/eval/phase3_gate_leak.test.js

# 3. Canvas Redactor Sync & Pixel Sampling Tests
node --test veil/eval/phase3_redactor.test.js

# 4. Vault Encryption & Session Tokenizer Tests
node --test veil/eval/phase3_unit.test.js

# 5. Network Isolation Invariant 2 Enforcement
node --test veil/eval/phase3_network_isolation.test.js
```

---

## 🔒 Security & Privacy Invariants

- **Invariant 1**: Server output is untrusted; the client validates every single action.
- **Invariant 2**: Only `privacy/gate.js` may make network calls (enforced by AST tests).
- **Invariant 3**: Never read, store, or transmit form input values.
- **Invariant 4**: Real PII lives strictly in the local encrypted vault and is resolved on-device at execution time.
- **Invariant 5**: Fail closed: any error or timeout degrades cleanly to solid black.
- **Invariant 6**: Server never logs request or response bodies; logs contain request IDs, sizes, timings, and error codes only.
