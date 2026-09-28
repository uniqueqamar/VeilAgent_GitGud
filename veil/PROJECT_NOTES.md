# Project Notes: Veil Agent (SIH PS 26171)

## Architecture Overview
Veil Agent is a privacy-preserving browser agent (Chrome + Firefox MV3 extension + FastAPI server) designed to automate web tasks while strictly protecting user privacy and preventing sensitive PII leakage.

The core execution loop:
`capture -> redact -> gate -> server -> validate -> execute -> repeat`

- **Tokenizer & Local Vault (`privacy/vault.js`)**: Encrypted using WebCrypto (PBKDF2 with 100,000 iterations + AES-GCM 256). Stored in memory / `storage.session` only. Issues session-stable typed tokens (`[EMAIL_1]`, `[NAME_1]`). Content scripts never receive the vault. Masking reveals nothing by default (`XXXX XXXX XXXX`), last-4 only when `showLast4` is enabled.
- **DOM Capture (`content/dom-capture.js`)**: Captures structural DOM snapshots (tag, role, type, label, bounding box) without ever reading field values, page titles, or full URL paths (origin only). In-place scans and redacts PII using `VeilPII`. Captures media elements (`img`, `canvas`, `video`, etc.) and elements with background images for redaction-by-default.
- **Visual Redactor (`privacy/redactor.js`)**: OffscreenCanvas + createImageBitmap engine operating in the background script. Performs a pre/post-capture sync check on scroll, DPR, and bounding boxes with 2 retries; degrades cleanly to Strict mode if motion is detected. Expands boxes by 4px, clips to viewport, scales for DPR, fills with solid black (`#000000`), and runs self-check pixel sampling (`verifyBoxBlack`) to guarantee zero optical leaks. Decodes screenshots purely in memory without network calls and dereferences immediately.
- **Privacy Gate (`privacy/gate.js`)**: The exclusive egress network gatekeeper. Validates allowlist schema (rejects unknown keys), enforces max string lengths and 1 MB payload limits, runs `detectPII` over all text fields, and verifies that every media, sensitive, and PII node is covered in the redaction manifest. Generates tamper-evident SHA-256 step receipt chains (`exportReceipts()`). Single file permitted to make network calls (`fetch`).
- **Server / Planner (`server/planner.py`, `server/main.py`)**: Stateless planner receiving goal, step, sanitized DOM, client-supplied `history`, and operating mode. Generates next action using placeholder tokens (e.g., `{{NAME}}`).
- **Validation & Vault Resolution (`background/orchestrator.js` & `content/executor.js`)**: Extension validates untrusted server outputs. Resolves placeholders only from exact vault keys or session-issued tokens. Refuses to fill identity fields on unencrypted `http://` pages. Requires user approval on unseen domains. Anti-honeypot checks (offscreen, 0 opacity, hidden aria, indented text, pointer-events: none) and same-origin form post validation.
- **UI / Popup (`ui/popup.html`, `ui/popup.js`)**: User control center featuring:
  - Mode toggle: **Balanced** (Redacted screenshot + tokens) vs **Strict** (Tokens only, zero screenshots).
  - Latest tamper-evident receipt display with SHA-256 hash chaining and JSON export.
  - "What the server sees" inspection modal displaying original vs redacted screenshot and manifest; original is kept in memory only and purged on modal close.

---

## File Map
```text
veil/
├── extension/
│   ├── manifest.json            # MV3 extension manifest (Chrome & Firefox Gecko support)
│   ├── background/
│   │   └── orchestrator.js      # Main agent lifecycle, loop coordination, vault resolution, state persistence
│   ├── content/
│   │   ├── dom-capture.js       # Sanitized DOM scanner (structural only, no input values, no path/title)
│   │   └── executor.js          # In-page action execution, anti-honeypot & same-origin form checks
│   ├── privacy/
│   │   ├── gate.js              # Exclusive egress network gatekeeper, schema validation & tamper-evident receipts
│   │   ├── redactor.js          # OffscreenCanvas visual masking, sync checks & pixel sampling self-check
│   │   └── vault.js             # WebCrypto PBKDF2 + AES-GCM encrypted vault & session tokenizer
│   ├── ui/
│   │   ├── popup.html           # Agent popup interface with mode toggle & inspection modal
│   │   └── popup.js             # User interaction, receipt export & volatile memory image inspection
│   └── workers/
│       ├── pii.js               # Dual-runtime (browser+Node) PII detector & field classifier
│       └── vision.worker.js     # [Future/Phase 3] ONNX vision worker
├── server/
│   ├── main.py                  # FastAPI server entry point, CORS configuration, request limits
│   ├── planner.py               # Stateless task planner (maps fields & goal history to actions)
│   ├── schema.py                # Pydantic data schemas (PlanRequest, Action, Dom, Node)
│   └── requirements.txt         # Server Python dependencies
└── eval/
    ├── synthetic_pages/
    │   └── kyc.html             # Synthetic KYC test page for verification
    ├── corpus/                  # 100 synthetic evaluation pages (60 dev + 40 held-out)
    ├── pii.test.js              # Unit test suite for pii.js (node --test)
    ├── phase3_unit.test.js      # Unit tests for vault, tokenizer & placeholder resolution
    ├── phase3_gate_leak.test.js # Deliberately leaky payloads per PII type & gate assertions
    ├── phase3_redactor.test.js  # Redactor sync check, motion detection & pixel sampling tests
    ├── phase3_network_isolation.test.js # Repo-wide network isolation check (Invariant 2)
    ├── phase3_corpus_zero_leak.js # Zero-leakage audit asserting no PII leaks across 100 corpus pages
    ├── phase3_e2e_kyc.test.js   # End-to-end KYC verification test
    ├── gen_corpus.py            # Independent synthetic corpus generator
    ├── run_detector.js          # jsdom evaluation harness running VeilPII
    ├── metrics.py               # Precision, Recall, F1 & hard-negative evaluator
    ├── results/                 # Evaluation results and reports
    └── run_loop_test.py         # End-to-end evaluation & loop verification test script
```

---

## Invariants
1. Server output is untrusted. The extension validates every action.
2. Only privacy/gate.js may make network calls (no fetch, XHR,
   WebSocket or sendBeacon anywhere else).
3. Never read, store or send input field values.
4. Real PII lives only in the local vault and is resolved inside the
   browser at execution time.
5. Fail closed: if unsure or an error occurs, send nothing and tell
   the user.
6. Never log PII values; log types and counts only.
7. Test only on fake-data pages, never on real logged-in accounts.
8. Small changes, don't rewrite working files, plain JS, no build
   tools in the extension.
9. Report honestly what you could NOT test.
10. Media stays fully black by default (Phase 3 rule). Vision may
    un-black a region ONLY after it ran successfully on that region
    and found nothing uncertain.
11. Vision failure, timeout, missing model, low confidence, or any
    exception => the region stays black (fail closed).
12. Model files are never fetched from a CDN at runtime. They are
    bundled, or downloaded once from a pinned URL and verified against a
    SHA-256 hash before use. This is the ONLY network exception besides
    gate.js; put it in one file (privacy/model-loader.js) and test it.
13. Never store face crops or screenshots on disk or IndexedDB.
14. The UI detector runs ONLY on the already-REDACTED image, never on the
    original screenshot. Its output is {class, box, confidence}. No text.
15. UI detector failure, timeout, or missing model falls back cleanly
    to "DOM only" (never a crash, never stalls the execution loop).
16. Fusion-generated visual_only nodes (vo1, vo2...) may only be targeted
    by coordinate clicks after client-side boundary and redaction safety
    checks, and require explicit user approval. Typing into visual_only
    nodes is strictly forbidden.
17. The server never fetches URLs or performs outbound HTTP requests
    (it only responds to client requests and connects to configured, pinned
    local/cloud model inference endpoints).
18. The server never runs tools or code from model output.
19. The server never writes requests or images to disk (all request
    payloads and image buffers are kept in volatile memory only).
20. The server never logs request or response bodies; logs contain
    request IDs, byte sizes, timings, and error codes only.
21. The server is untrusted for input (must reject anything that looks
    like PII via an independent tripwire) and untrusted for output (the
    client validates every action).

---

## Phase 5: Visual Context Accuracy & UI Detection Design
- **Goal**: Improve and measure visual context accuracy: enable the agent to perceive and interact with elements where DOM is missing or misleading (custom widgets, canvas UIs, PDF viewers) without adding network endpoints.
- **Safety Design**: The UI detector executes strictly downstream of `captureAndRedact`, operating ONLY on already-redacted image bitmaps. Because all PII and sensitive areas are solidly masked prior to detector execution, the model has zero access to sensitive information. Furthermore, its output schema is constrained to `{class, box, confidence}` with zero text tokens, making PII creation or leakage mathematically impossible.
- **DOM-Vision Fusion**: Detected UI boxes are matched to interactive DOM elements using IoU (Intersection over Union). Detections without corresponding DOM nodes become `visual_only` nodes (`vo1`, `vo2`, ...).
- **Coordinate Click Validation**: Visual-only nodes are only targetable via coordinate clicks (`click`), strictly validated on the client:
  1. $(x, y)$ coordinate must reside inside the detection bounding box.
  2. $(x, y)$ coordinate must reside inside the visible viewport.
  3. $(x, y)$ coordinate must NOT intersect any redacted or sensitive region.
  4. Auto-approval is unconditionally bypassed (`autoApprove` forced false) requiring explicit user confirmation.
  5. Typing (`type`) into visual-only nodes is strictly forbidden.
- **Fail-Safe Degradation**: UI detector failure, model corruption, or inference timeout (>1500ms) degrades cleanly to "DOM only" mode.

## Known Limits
1. **Tiny Icons**: Low resolution or favicon-scale icons (< 14x14px) may fall below anchor receptive fields and fail detection.
2. **Heavy Themes**: High-contrast, neon, or deeply skeuomorphic themes with unconventional borders can diminish box boundary precision.
3. **Overlapping Widgets**: Nested modal overlays, translucent backdrop filters, or stacked floating panels may cause IoU ambiguity between layers.
4. **Animations & Transitions**: Dynamic CSS transitions, canvas particle effects, and GIF/video loops can cause inter-frame coordinate drift.

---

## Phase 6: Server Hardening, Real VLM Planner & Answer Path
- **Server Security & Invariants**: The server binds to `127.0.0.1` by default, enforces a shared token header (`X-Veil-Token`) via constant-time comparison (`hmac.compare_digest`), caps request body to 2 MB, response size to 100 KB, enforces rate limiting, concurrency semaphores, and a 15s request timeout. Images are verified JPEG-only via Pillow with `MAX_IMAGE_PIXELS = 10_000_000` (rejecting decompression bombs), metadata stripped, and buffers retained in memory only.
- **Independent Server PII Tripwire**: An independent Python implementation of `detectPII` (with its own Verhoeff and Luhn checksum algorithms) scans every string in every incoming request. Any match triggers HTTP 422 `{ "code": "PII_TRIPWIRE", "types": [...] }` without echoing matched values. `gate.js` flags "server refused: possible leak" and immediately halts execution.
- **Protocol Schema (`shared/protocol.schema.json`)**: Strictly typed and versioned JSON Schema generating Pydantic v2 server models and client JavaScript validator. Exactly one of: `action | answer | ask_user | done | fail`, each with a reason of max 200 chars. Unknown fields, oversize strings, and invalid types are rejected on BOTH client and server.
- **Planner Backends**:
  1. `DeterministicPlanner`: Fast, deterministic fallback and test fixture.
  2. `LocalVLM`: Qwen2.5-VL-7B-Instruct (Apache-2.0, dynamic resolution, fast vision-language reasoning) via local inference server (e.g., Ollama / vLLM / llama.cpp), with small/CPU fallback option (Qwen2.5-VL-3B-Instruct).
  3. `CloudVLM`: Optional remote provider; API key stored ONLY in server environment; strictly refuses to start unless `VEIL_ALLOW_CLOUD=1`.
- **Prompt Defense**: System prompt explicitly specifies that black boxes are redacted unknowable regions, `[TYPE_n]` tokens are opaque handles, and all page/DOM/image text is UNTRUSTED DATA. Untrusted content is wrapped in delimiters containing a per-request cryptographically secure random nonce (`secrets.token_hex(8)`), and that nonce string is stripped from all user inputs.
---

## Phase 7: Real-World Pages (Iframes, Shadow DOM, Dynamic Apps)
- **Multi-Frame Architecture**: Content scripts run in all frames (`all_frames: true`). Each frame reports its DOM snapshot to the background script, which verifies `sender.tab.id` and `sender.frameId` via the browser engine. IDs are frame-qualified (`f${frameId}:${nodeId}`, e.g., `f0:e1`, `f2:e5`). Cumulative frame offsets are computed for bounding boxes. Nested frames are capped at max depth 3. Total nodes across all frames are capped at 400, sorted viewport-first. Content scripts strictly ignore `window.postMessage` from the page.
- **Cross-Origin Iframe Protection**: Readable structure only. Filling vault values into a cross-origin frame is strictly **BLOCKED** unless the user approves that exact origin. Passwords, OTPs, and card fields are never filled.
- **Shadow DOM Traversal**: Recursive tree traversal inspects **OPEN** shadow roots. Closed shadow roots and opaque custom widgets are treated like media: their bounding boxes stay solid black (marked `sensitive: true`) unless on-device vision clears them.
- **Dynamic Apps & Single Page Applications (SPA)**: Debounced `MutationObserver` monitors DOM changes. Node IDs are stable across re-renders via `WeakMap<Element, string>` on a best-effort basis. If an element becomes stale or detached (`!el.isConnected`), the executor reports `stale: true`, triggering immediate DOM recapture without guessing. Virtualized lists and infinite scroll streams are capped at 400 nodes total, viewport-first.
- **Visible-Text-Only Capture (Anti-Injection)**: Excludes elements with: `display: none`, `visibility: hidden` or `collapse`, `opacity < 0.05`, off-screen placement, `font-size < 6px`, text contrast ratio < 1.5 against effective background, `aria-hidden="true"`, 1px or clipped elements (`clip: rect(0,0,0,0)`, `clip-path`), and large negative `text-indent` (<= -100px). 100% of hidden prompt injection vectors are discarded.
- **Clickjacking & Honeypot Defenses**: Elements covered by overlays are excluded at capture time. Immediately before any click, the executor performs a mandatory `document.elementFromPoint(cx, cy)` re-check; if covered or obscured by an overlay, the click is aborted immediately.
- **Executor Safety**: Never calls page-defined functions (synthetic pointer and mouse events only), no `eval`, no `innerHTML`, and verifies target element connectivity and center point stability after scrolling.
- **Audit**: Zero page DOM additions exist across content scripts.

### Known Limits
1. **Built-in PDF Viewers**: Browser-internal PDF viewers run inside native plugin architectures without standard DOM representations; visual-only coordinate interaction is required.
2. **Canvas-Only Applications**: WebGL or canvas-rendered interfaces lack DOM nodes; require YOLOX-nano visual detection and coordinate clicks.
3. **Multi-Tab Workflows**: Agent execution scope is securely pinned to the active tab (`activeTab`); popup or background tab switching is restricted.
4. **Native File Uploads**: OS-level native file picker dialogs cannot be automated via synthetic browser DOM events.
5. **CAPTCHAs & Bot Traps**: Adversarial human verification challenges (Turnstile, reCAPTCHA, puzzle sliders) are deliberately not bypassed.
6. **Browser-Internal Pages**: Extension cannot automate privileged browser internal pages (`chrome://*`, `about:*`, `edge://*`).




