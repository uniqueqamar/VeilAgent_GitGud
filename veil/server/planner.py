"""Planner interface with three backends (Task 4, 5, 6).

Backends:
1. DeterministicPlanner: Kept for fast tests and predictable baseline tasks.
2. LocalVLM: Qwen2.5-VL (Qwen2.5-VL-7B-Instruct / Qwen2.5-VL-3B-Instruct)
   - License: Apache-2.0
   - Architecture: Native dynamic resolution Vision-Language Model
   - Justification: Apache-2.0 permissive license (no AGPL obligations),
     7B fits in 16GB VRAM (or 6-8GB with 4-bit quant), 3B runs on CPU/weak machines.
3. CloudVLM: Optional remote provider; API key lives ONLY in server env;
   refuses to start unless VEIL_ALLOW_CLOUD=1.
"""
import abc
import asyncio
import base64
import collections.abc
import os
import json
import logging
from typing import Optional

from prompt import (
    build_prompt_payload,
    convert_dict_to_response,
    parse_model_response,
)
from schema import (
    ActionResponse,
    AnswerResponse,
    AskUserResponse,
    DoneResponse,
    FailResponse,
    PlanRequest,
    PlanResponse,
)
from validator import validate_planned_action

logger = logging.getLogger("veil.planner")


class BasePlanner(abc.ABC):
    @abc.abstractmethod
    async def plan(self, req: PlanRequest, image_bytes: Optional[bytes] = None) -> PlanResponse:
        """Generate the next agent step given request context and optional image."""
        pass


class DeterministicPlanner(BasePlanner):
    """Deterministic fallback and test planner fixture."""

    FILL_MAP = [
        ("father", "{{FATHER_NAME}}"),
        ("pita", "{{FATHER_NAME}}"),
        ("mother", "{{MOTHER_NAME}}"),
        ("mata", "{{MOTHER_NAME}}"),
        ("first name", "{{FIRST_NAME}}"),
        ("last name", "{{LAST_NAME}}"),
        ("full name", "{{FULL_NAME}}"),
        ("name", "{{FULL_NAME}}"),
        ("email", "{{EMAIL}}"),
        ("mobile", "{{MOBILE}}"),
        ("phone", "{{MOBILE}}"),
        ("date of birth", "{{DOB}}"),
        ("dob", "{{DOB}}"),
        ("birth", "{{DOB}}"),
        ("gender", "{{GENDER}}"),
        ("sex", "{{GENDER}}"),
        ("address line 2", "{{ADDRESS_LINE2}}"),
        ("address line 1", "{{ADDRESS_LINE1}}"),
        ("address", "{{ADDRESS_LINE1}}"),
        ("city", "{{CITY}}"),
        ("district", "{{DISTRICT}}"),
        ("state", "{{STATE}}"),
        ("pin", "{{PIN}}"),
        ("pincode", "{{PIN}}"),
        ("aadhaar", "{{AADHAAR}}"),
        ("pan", "{{PAN}}"),
        ("ifsc", "{{IFSC}}"),
        ("account", "{{ACCOUNT_NO}}"),
        ("category", "{{CATEGORY}}"),
    ]

    async def plan(self, req: PlanRequest, image_bytes: Optional[bytes] = None) -> PlanResponse:
        goal_lower = req.goal.lower()

        # Task 7: Answer path for summarization goals
        if any(w in goal_lower for w in ("summarize", "summary", "what is", "read page")):
            page_text_snippets = []
            for n in req.dom.nodes:
                if n.text and not n.sensitive:
                    page_text_snippets.append(n.text.strip())
                elif n.label and not n.sensitive:
                    page_text_snippets.append(n.label.strip())
            summary = "Summary: " + " ".join(page_text_snippets[:10])
            if len(summary) > 1900:
                summary = summary[:1900] + "..."
            return AnswerResponse(
                type="answer",
                text=summary or "Summary of the requested page context.",
                reason="summarized page contents as requested"
            )

        # Form filling and interactive tasks
        done_targets = set()
        for h in req.history:
            if h.target_id:
                done_targets.add(h.target_id)

        for n in req.dom.nodes:
            if n.tag in ("input", "textarea") and not n.sensitive and n.id not in done_targets:
                itype = (n.type or "").lower()
                if itype in ("submit", "button", "hidden"):
                    continue

                label = (n.label or "").lower()
                text = (n.text or "").lower()
                combined_desc = f"{label} {text} {n.id}".lower()

                # Phase 8: Disambiguation checks (company/org is NOT personal full name)
                if "company" in combined_desc or "organization" in combined_desc or "institution" in combined_desc:
                    return AskUserResponse(
                        type="ask_user",
                        question=f"Please provide your organization name for '{n.label or n.id}'",
                        reason="organization name is not in personal vault"
                    )

                # Check known vault keys
                matched_placeholder = None
                for key_token, placeholder in self.FILL_MAP:
                    if key_token in combined_desc:
                        # Negative checks for personal name
                        if placeholder == "{{FULL_NAME}}" and any(neg in combined_desc for neg in ("father", "mother", "pita", "mata", "first", "last")):
                            continue
                        matched_placeholder = placeholder
                        break

                if matched_placeholder:
                    return ActionResponse(
                        type="action",
                        action="type",
                        target_id=n.id,
                        value=matched_placeholder,
                        reason=f"fill '{n.label or n.id}'"
                    )

                # Phase 8: Free-text fields drafting (why are you applying, remarks, purpose)
                if any(w in combined_desc for w in ("why", "purpose", "reason", "remarks", "statement of purpose", "comment", "feedback")):
                    draft = f"Applying for {req.goal} based on eligibility requirements."
                    return ActionResponse(
                        type="action",
                        action="type",
                        target_id=n.id,
                        value=draft,
                        reason=f"draft free text for '{n.label or n.id}' based on goal"
                    )

                # Unknown field with no matching vault key (Invariant: never guess, ask user)
                return AskUserResponse(
                    type="ask_user",
                    question=f"Please provide value for field '{n.label or n.id}'",
                    reason="unrecognized field without matching vault key"
                )

        if "submit" in goal_lower:
            for n in req.dom.nodes:
                is_btn = (
                    n.tag == "button"
                    or n.role == "button"
                    or (n.tag == "input" and (n.type or "").lower() in ("submit", "button"))
                )
                if is_btn and "submit" in (n.label or "").lower() and n.id not in done_targets:
                    return ActionResponse(
                        type="action",
                        action="click",
                        target_id=n.id,
                        reason="submit form"
                    )

        # Coordinate clicks for visual-only nodes if requested
        for n in req.dom.nodes:
            if n.id.startswith("vo") and n.id not in done_targets:
                x = n.bbox[0] + n.bbox[2] // 2
                y = n.bbox[1] + n.bbox[3] // 2
                return ActionResponse(
                    type="action",
                    action="click",
                    target_id=n.id,
                    coords=[x, y],
                    reason=f"click visual element {n.id}"
                )

        return DoneResponse(
            type="done",
            reason="all identified actions completed"
        )


class LocalVLM(BasePlanner):
    """Qwen2.5-VL via local inference server (Ollama, vLLM, or llama.cpp).
    Pinned Models:
    - Default: Qwen2.5-VL-7B-Instruct (Apache-2.0)
    - Small / CPU option: Qwen2.5-VL-3B-Instruct (Apache-2.0)
    """

    def __init__(self):
        self.endpoint = os.getenv("LOCAL_VLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
        # Support small/CPU model for weak machines
        use_small = os.getenv("VEIL_SMALL_MODEL", "0") == "1"
        self.model = os.getenv("LOCAL_VLM_MODEL", "qwen2.5-vl:3b" if use_small else "qwen2.5-vl:7b")
        self.timeout = float(os.getenv("LOCAL_VLM_TIMEOUT", "12.0"))

    async def _call_inference(self, messages: list) -> Optional[str]:
        import urllib.request
        import urllib.error

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 512,
            "response_format": {"type": "json_object"}
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                return res_json["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"LocalVLM inference call failed: {e}")
            return None

    async def plan(self, req: PlanRequest, image_bytes: Optional[bytes] = None) -> PlanResponse:
        system_prompt, user_prompt, nonce = build_prompt_payload(req)

        user_content = []
        if image_bytes:
            b64_img = base64.b64encode(image_bytes).decode("ascii")
            user_content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{b64_img}"}
            })
        elif req.image:
            img_data = req.image
            if not img_data.startswith("data:"):
                img_data = f"data:image/jpeg;base64,{img_data}"
            user_content.append({
                "type": "image_url",
                "image_url": {"url": img_data}
            })

        user_content.append({"type": "text", "text": user_prompt})

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

        raw_output = await self._call_inference(messages)
        parsed = parse_model_response(raw_output) if raw_output else None

        # At most ONE repair retry if output fails schema
        if not parsed and raw_output:
            logger.info("LocalVLM response failed schema, attempting single repair retry")
            repair_messages = list(messages)
            repair_messages.append({"role": "assistant", "content": raw_output})
            repair_messages.append({
                "role": "user",
                "content": "Your previous response was not valid JSON conforming to the protocol schema. Output ONLY valid JSON."
            })
            retry_output = await self._call_inference(repair_messages)
            parsed = parse_model_response(retry_output) if retry_output else None

        if not parsed:
            # Fallback cleanly
            logger.warning("LocalVLM failed to produce schema-valid response; returning fail")
            return FailResponse(
                type="fail",
                reason="LocalVLM failed to produce schema-valid JSON response"
            )

        return convert_dict_to_response(parsed)


class CloudVLM(BasePlanner):
    """Optional Cloud Vision-Language Model.
    Strictly refuses to start unless VEIL_ALLOW_CLOUD=1 is explicitly set.
    API key is read ONLY from server environment.
    """

    def __init__(self):
        if os.getenv("VEIL_ALLOW_CLOUD", "0") != "1":
            raise RuntimeError(
                "CloudVLM is disabled. Set VEIL_ALLOW_CLOUD=1 in the server environment to enable. "
                "Notice: When enabled, a third-party cloud provider receives the redacted context."
            )
        self.api_key = os.getenv("VEIL_CLOUD_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("VEIL_CLOUD_API_KEY must be set in server environment when CloudVLM is enabled.")
        self.provider_url = os.getenv("VEIL_CLOUD_URL", "https://api.openai.com/v1/chat/completions")
        self.model = os.getenv("VEIL_CLOUD_MODEL", "gpt-4o-mini")
        self.timeout = float(os.getenv("VEIL_CLOUD_TIMEOUT", "15.0"))

    async def _call_inference(self, messages: list) -> Optional[str]:
        import urllib.request

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 512,
            "response_format": {"type": "json_object"}
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.provider_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                return res_json["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"CloudVLM inference failed: {e}")
            return None

    async def plan(self, req: PlanRequest, image_bytes: Optional[bytes] = None) -> PlanResponse:
        system_prompt, user_prompt, nonce = build_prompt_payload(req)

        user_content = []
        if image_bytes:
            b64_img = base64.b64encode(image_bytes).decode("ascii")
            user_content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{b64_img}"}
            })
        elif req.image:
            img_data = req.image
            if not img_data.startswith("data:"):
                img_data = f"data:image/jpeg;base64,{img_data}"
            user_content.append({
                "type": "image_url",
                "image_url": {"url": img_data}
            })

        user_content.append({"type": "text", "text": user_prompt})

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

        raw_output = await self._call_inference(messages)
        parsed = parse_model_response(raw_output) if raw_output else None

        if not parsed and raw_output:
            repair_messages = list(messages)
            repair_messages.append({"role": "assistant", "content": raw_output})
            repair_messages.append({
                "role": "user",
                "content": "Your response was not schema-valid JSON. Output ONLY JSON."
            })
            retry_output = await self._call_inference(repair_messages)
            parsed = parse_model_response(retry_output) if retry_output else None

        if not parsed:
            return FailResponse(
                type="fail",
                reason="CloudVLM failed to produce schema-valid response"
            )

        return convert_dict_to_response(parsed)


# Active planner registry
_ACTIVE_PLANNER: Optional[BasePlanner] = None


def get_planner() -> BasePlanner:
    """Retrieve or instantiate the configured planner backend."""
    global _ACTIVE_PLANNER
    if _ACTIVE_PLANNER is not None:
        return _ACTIVE_PLANNER

    backend = os.getenv("VEIL_PLANNER_BACKEND", "deterministic").lower()
    if backend == "local_vlm":
        _ACTIVE_PLANNER = LocalVLM()
    elif backend == "cloud_vlm":
        _ACTIVE_PLANNER = CloudVLM()
    else:
        _ACTIVE_PLANNER = DeterministicPlanner()

    return _ACTIVE_PLANNER


def set_planner(planner: BasePlanner) -> None:
    """Explicitly set planner backend (useful for tests)."""
    global _ACTIVE_PLANNER
    _ACTIVE_PLANNER = planner


class PlanCoroutineWrapper(collections.abc.Coroutine):
    """Transparent coroutine wrapper enabling both sync attribute access and async/await/asyncio.run support."""
    def __init__(self, response: PlanResponse):
        self._response = response
        self._coro = None

    def _ensure_coro(self):
        if self._coro is None:
            self._coro = self._run()
        return self._coro

    async def _run(self):
        return self._response

    def send(self, val):
        return self._ensure_coro().send(val)

    def throw(self, *args):
        return self._ensure_coro().throw(*args)

    def close(self):
        if self._coro is not None:
            return self._coro.close()

    def __await__(self):
        return self._ensure_coro().__await__()

    def __getattr__(self, name):
        return getattr(self._response, name)


async def _plan_async(req: PlanRequest, image_bytes: Optional[bytes] = None) -> PlanResponse:
    """Async core planning logic with server defense-in-depth checks."""
    planner = get_planner()
    raw_response = await planner.plan(req, image_bytes)
    # Server defense-in-depth validation
    safe_response = validate_planned_action(raw_response, req)
    return safe_response


def plan(req: PlanRequest, image_bytes: Optional[bytes] = None):
    """Top-level planning function supporting sync callers, asyncio.run(), and FastAPI await seamlessly."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        return _plan_async(req, image_bytes)
    else:
        res = asyncio.run(_plan_async(req, image_bytes))
        return PlanCoroutineWrapper(res)

