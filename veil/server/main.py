"""Veil Agent Hardened Server (Tasks 1, 2, 3, 4, 6, 10).
Invariants:
17. Server never fetches URLs or performs outbound HTTP requests (only calls pinned local/cloud inference).
18. Server never runs tools or code from model output.
19. Server never writes requests or images to disk (all volatile memory only).
20. Server never logs request or response bodies; logs contain request IDs, sizes, timings, and error codes only.
21. Server is untrusted for input (rejects PII via tripwire) and untrusted for output (client validates every action).
"""
import asyncio
import base64
import collections
import hmac
import io
import json
import logging
import os
import time
import uuid
from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from PIL import Image

from planner import get_planner, plan
from schema import (
    ActionResponse,
    AnswerResponse,
    AskUserResponse,
    DoneResponse,
    FailResponse,
    PlanRequest,
    PlanResponse,
)
from tripwire import scan_payload_for_pii

# Configure strict privacy logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("veil.server")

# Security and resource caps
MAX_REQUEST_SIZE = 2_000_000   # 2 MB limit
MAX_RESPONSE_SIZE = 100_000    # 100 KB limit
REQUEST_TIMEOUT_SECONDS = 15.0 # 15s per-request timeout
MAX_CONCURRENT_REQUESTS = 10   # concurrency cap
RATE_LIMIT_PER_MINUTE = 120    # per-token rate limit
Image.MAX_IMAGE_PIXELS = 10_000_000  # Decompression bomb cap

# Token auth configuration
SERVER_TOKEN = os.getenv("VEIL_SERVER_TOKEN", "veil-shared-secret-token")

# Canary Mode Configuration (Task 2 & Invariant 15)
VEIL_CANARY = os.getenv("VEIL_CANARY", "0") == "1"
VEIL_ALLOW_CLOUD = os.getenv("VEIL_ALLOW_CLOUD", "0") == "1"

if VEIL_CANARY and VEIL_ALLOW_CLOUD:
    raise RuntimeError("Security Violation: VEIL_CANARY=1 is strictly forbidden when cloud mode is active.")

canary_registry: set[str] = set()
canary_field_hits: Dict[str, int] = collections.defaultdict(int)


def scan_dict_for_canaries(obj, path="payload"):
    if not canary_registry:
        return
    if isinstance(obj, str):
        for c in canary_registry:
            if c and c in obj:
                canary_field_hits[path] += 1
    elif isinstance(obj, dict):
        for k, v in obj.items():
            scan_dict_for_canaries(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            scan_dict_for_canaries(item, f"{path}[{idx}]")

# In-memory concurrency and rate-limiting structures
concurrency_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
token_rate_tracker: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

app = FastAPI(title="Veil Agent Hardened Server", docs_url=None, redoc_url=None)

# Lock CORS strictly to browser extension protocols & local test harnesses
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension|moz-extension)://.*$|http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Latency-Ms"]
)


@app.middleware("http")
async def security_and_audit_guard(request: Request, call_next):
    req_id = uuid.uuid4().hex[:12]
    start_time = time.perf_counter()
    status_code = 500
    error_code = "NONE"
    body_in_bytes = 0
    body_out_bytes = 0

    try:
        # 1. Enforce Request Body Size Cap (2 MB)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE:
            status_code = 413
            error_code = "PAYLOAD_TOO_LARGE"
            return JSONResponse(status_code=413, content={"error": "Payload exceeds 2 MB limit"})

        # 2. Token Authentication (Constant-time comparison)
        # Exclude /health, /canary/*, and OPTIONS from token authentication
        is_canary_path = VEIL_CANARY and request.url.path.startswith("/canary")
        if request.url.path not in ("/health", "/docs", "/openapi.json") and not is_canary_path and request.method != "OPTIONS":
            token_hdr = request.headers.get("x-veil-token", "")
            if not token_hdr or not hmac.compare_digest(token_hdr.encode("utf-8"), SERVER_TOKEN.encode("utf-8")):
                status_code = 401
                error_code = "UNAUTHORIZED"
                return JSONResponse(status_code=401, content={"error": "Unauthorized: invalid or missing X-Veil-Token"})

            # 3. Rate Limiting per token (sliding 60s window)
            now = time.time()
            timestamps = token_rate_tracker[token_hdr]
            while timestamps and now - timestamps[0] > 60.0:
                timestamps.popleft()
            if len(timestamps) >= RATE_LIMIT_PER_MINUTE:
                status_code = 429
                error_code = "RATE_LIMIT_EXCEEDED"
                return JSONResponse(status_code=429, content={"error": "Too Many Requests: rate limit exceeded"})
            timestamps.append(now)

        # 4. Concurrency Cap
        try:
            acquired = concurrency_semaphore.locked() and concurrency_semaphore._value == 0
            if acquired:
                status_code = 503
                error_code = "CONCURRENCY_LIMIT"
                return JSONResponse(status_code=503, content={"error": "Server busy: concurrency cap reached"})

            async with concurrency_semaphore:
                # 5. Request Timeout
                try:
                    response = await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    status_code = 504
                    error_code = "GATEWAY_TIMEOUT"
                    return JSONResponse(status_code=504, content={"error": "Request timed out after 15s"})
        except Exception as ex:
            status_code = 500
            error_code = type(ex).__name__
            raise

        status_code = response.status_code

        # 6. Response Size Cap (100 KB)
        resp_len = response.headers.get("content-length")
        if resp_len and int(resp_len) > MAX_RESPONSE_SIZE:
            status_code = 500
            error_code = "RESPONSE_TOO_LARGE"
            return JSONResponse(status_code=500, content={"error": "Response exceeded 100 KB limit"})

        # 7. Add Strict Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["X-Request-ID"] = req_id

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response.headers["X-Latency-Ms"] = str(duration_ms)
        return response

    finally:
        # Invariant 20: Logs contain ONLY request id, sizes, timings and error codes (NEVER bodies)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            f"req_id={req_id} method={request.method} path={request.url.path} "
            f"status={status_code} in_bytes={content_length or 0} "
            f"duration={duration_ms}ms error={error_code}"
        )


@app.get("/health")
def health():
    """Health check endpoint showing model status only (no secrets or environment variables)."""
    planner = get_planner()
    backend_name = type(planner).__name__
    model_name = getattr(planner, "model", "rules-engine")
    return {
        "ok": True,
        "model": {
            "backend": backend_name,
            "model": model_name,
            "status": "ready"
        }
    }


def process_image_securely(image_str: Optional[str]) -> Optional[bytes]:
    """Decode, sanitize, and verify image in memory (JPEG only, decompression bomb check, strip metadata).
    Returns sanitized JPEG bytes in memory only (never written to disk).
    """
    if not image_str:
        return None

    # Strip data URL header if present
    raw_b64 = image_str
    if "," in raw_b64:
        raw_b64 = raw_b64.split(",", 1)[1]

    try:
        raw_bytes = base64.b64decode(raw_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding in image")

    if len(raw_bytes) > MAX_REQUEST_SIZE:
        raise HTTPException(status_code=413, detail="Image size exceeds 2 MB limit")

    bio_in = io.BytesIO(raw_bytes)

    try:
        # Pillow verification
        img = Image.open(bio_in)

        # Accept JPEG only
        if img.format != "JPEG":
            raise HTTPException(status_code=400, detail="Invalid image format: JPEG required")

        # Decompression bomb and size verification
        img.verify()
    except Image.DecompressionBombError:
        raise HTTPException(status_code=400, detail="Decompression bomb detected in image")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Image decoding failed: {e}")

    # Re-open to strip all metadata and re-encode to clean in-memory buffer
    bio_in.seek(0)
    img_opened = Image.open(bio_in)

    # Convert to RGB (in case of CMYK or grayscale)
    if img_opened.mode != "RGB":
        img_opened = img_opened.convert("RGB")

    # Strip metadata: save into clean buffer with no EXIF/IPTC
    bio_out = io.BytesIO()
    img_opened.save(bio_out, format="JPEG", quality=85, optimize=True)
    clean_bytes = bio_out.getvalue()
    bio_in.close()
    bio_out.close()

    # Retained in memory only (Invariant 19)
    return clean_bytes


@app.post("/plan")
async def plan_endpoint(request: Request):
    """Planner endpoint:
    1. Parse and validate JSON against protocol schema
    2. Run server PII tripwire over all request strings (Task 3)
    3. Process and sanitize image securely in memory (Task 2)
    4. Execute multi-backend planner with prompt injection defenses (Task 4, 5)
    5. Enforce server defense-in-depth output validation (Task 6)
    """
    try:
        body_bytes = await request.body()
        if len(body_bytes) > MAX_REQUEST_SIZE:
            return JSONResponse(status_code=413, content={"error": "Payload exceeds 2 MB limit"})
        body_dict = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON payload: {e}"})

    # Task 2: Canary Leak Scanner (when VEIL_CANARY=1)
    if VEIL_CANARY:
        scan_dict_for_canaries(body_dict)

    # Task 3: Server Tripwire - Scan every string in request for unredacted PII
    pii_types_detected = scan_payload_for_pii(body_dict)
    if pii_types_detected:
        logger.warning(f"PII Tripwire triggered! Detected types: {pii_types_detected}")
        # Invariant 6 & Task 3: Never echo matched values, return HTTP 422
        return JSONResponse(
            status_code=422,
            content={
                "code": "PII_TRIPWIRE",
                "types": pii_types_detected
            }
        )

    # Parse with Pydantic model (rejects unknown fields via extra='forbid')
    try:
        plan_req = PlanRequest.model_validate(body_dict)
    except Exception as val_err:
        return JSONResponse(status_code=422, content={"error": f"Schema validation failed: {val_err}"})

    # Task 2: Process image with Pillow (JPEG only, decompression bomb check, memory only)
    image_bytes = None
    if plan_req.image:
        image_bytes = process_image_securely(plan_req.image)

    # Task 4 & 5: Plan action with configured backend and prompt defense
    response: PlanResponse = await plan(plan_req, image_bytes)

    # Convert Pydantic response model to JSON dict
    resp_dict = response.model_dump(exclude_none=True)

    # Enforce response cap
    resp_bytes = json.dumps(resp_dict).encode("utf-8")
    if len(resp_bytes) > MAX_RESPONSE_SIZE:
        return JSONResponse(status_code=500, content={"error": "Response size exceeds cap"})

    return JSONResponse(content=resp_dict)


# Canary Mode Endpoints (Active strictly when VEIL_CANARY=1, Localhost only)
if VEIL_CANARY:
    @app.post("/canary/register")
    async def canary_register(request: Request):
        try:
            data = await request.json()
            canaries = data.get("canaries", [])
            for c in canaries:
                if isinstance(c, str) and len(c.strip()) > 0:
                    canary_registry.add(c.strip())
            return {"ok": True, "registered_count": len(canary_registry)}
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

    @app.get("/canary/report")
    def canary_report():
        # Invariant 6 & 20: Return counts of hits per field, NEVER canary values
        return {
            "ok": True,
            "total_registered": len(canary_registry),
            "total_leaks": sum(canary_field_hits.values()),
            "hits_per_field": dict(canary_field_hits)
        }

    @app.post("/canary/reset")
    def canary_reset():
        canary_registry.clear()
        canary_field_hits.clear()
        return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    # Invariant: Bind strictly to 127.0.0.1 by default
    uvicorn.run(app, host="127.0.0.1", port=8000)
