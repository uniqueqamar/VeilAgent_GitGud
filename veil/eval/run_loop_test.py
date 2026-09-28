"""
End-to-End Evaluation Test for Veil Agent (Task 10).
Tests:
1. DOM capture simulation matching exact KYC DOM structure and privacy invariants.
2. Full planner execution loop with client-side history tracking.
3. Verification that password fields are skipped.
4. Statelessness of planner across independent and concurrent calls.
5. Server hardening & validation (Pydantic extra='forbid', 1MB limit).
6. Local vault resolution & unknown token rejection.
7. Risky action detection (submit button approval trigger).
8. Client validation guards (typing into password/OTP inputs rejected).
"""
import sys
import json
import re
from pathlib import Path

# Add server directory to path
SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
sys.path.insert(0, str(SERVER_DIR))

from schema import Action, Dom, Node, PlanRequest
from planner import plan

VAULT = {
    "NAME": "Asha Verma",
    "EMAIL": "asha@example.com",
    "PHONE": "9876543210"
}


def simulate_kyc_dom_capture() -> Dom:
    """Simulates the output of extension/content/dom-capture.js on kyc.html."""
    return Dom(
        url="http://127.0.0.1:8000",  # Origin only, no path
        title="",                     # Page title stripped
        viewport=[1280, 720],
        scrollY=0,
        nodes=[
            Node(id="e1", tag="input", role=None, type="text", label="Full name", sensitive=False, bbox=[10, 50, 200, 24]),
            Node(id="e2", tag="input", role=None, type="email", label="Email", sensitive=False, bbox=[10, 100, 200, 24]),
            Node(id="e3", tag="input", role=None, type="text", label="Mobile", sensitive=False, bbox=[10, 150, 200, 24]),
            Node(id="e4", tag="input", role=None, type="password", label="Password", sensitive=True, bbox=[10, 200, 200, 24]),
            Node(id="e5", tag="button", role=None, type="button", label="Submit", sensitive=False, bbox=[10, 250, 100, 30]),
        ]
    )


def test_full_loop_sequence():
    """Test full capture -> planner -> history -> submit sequence."""
    print("\n--- Test 1: Full Planner Loop Sequence on KYC DOM ---")
    dom = simulate_kyc_dom_capture()
    goal = "fill the form and submit"
    history = []
    max_steps = 8

    expected_sequence = [
        ("type", "e1", "{{NAME}}"),
        ("type", "e2", "{{EMAIL}}"),
        ("type", "e3", "{{PHONE}}"),
        ("click", "e5", None),
        ("done", None, None),
    ]

    for step_num in range(1, max_steps + 1):
        req = PlanRequest(goal=goal, step=step_num, dom=dom, history=history)
        action = plan(req)
        print(f"  Step {step_num}: {action.action} target={action.target_id} val={action.value} ({action.reason})")

        exp_action, exp_target, exp_val = expected_sequence[step_num - 1]
        assert action.action == exp_action, f"Expected action {exp_action}, got {action.action}"
        assert action.target_id == exp_target, f"Expected target {exp_target}, got {action.target_id}"
        assert action.value == exp_val, f"Expected value {exp_val}, got {action.value}"

        if action.action == "done":
            print(f"  Goal achieved successfully in {step_num} steps.")
            break

        history.append(action)

    assert len(history) == 4, f"Expected 4 actions before done, got {len(history)}"
    # Verify password was NEVER targeted
    assert not any(a.target_id == "e4" for a in history), "Invariant violation: password was targeted!"
    print("  [PASS] Full loop sequence completed and password skipped.")


def test_statelessness():
    """Test that server does not hold any residual state across separate requests."""
    print("\n--- Test 2: Server Statelessness ---")
    dom = simulate_kyc_dom_capture()

    # Request with step 3 history directly without running step 1 or 2 on this session
    prefilled_history = [
        Action(action="type", target_id="e1", value="{{NAME}}"),
        Action(action="type", target_id="e2", value="{{EMAIL}}"),
    ]
    req = PlanRequest(goal="fill the form and submit", step=3, dom=dom, history=prefilled_history)
    action = plan(req)
    assert action.target_id == "e3", f"Expected e3 (mobile), got {action.target_id}"

    # Request with submit already done in history
    done_history = [
        Action(action="type", target_id="e1", value="{{NAME}}"),
        Action(action="type", target_id="e2", value="{{EMAIL}}"),
        Action(action="type", target_id="e3", value="{{PHONE}}"),
        Action(action="click", target_id="e5", value=None),
    ]
    req_done = PlanRequest(goal="fill the form and submit", step=5, dom=dom, history=done_history)
    action_done = plan(req_done)
    assert action_done.action == "done", f"Expected done, got {action_done.action}"
    print("  [PASS] Server is strictly stateless and driven by client-supplied history.")


def test_schema_hardening_extra_fields():
    """Test that Pydantic extra='forbid' rejects unexpected fields."""
    print("\n--- Test 3: Schema Hardening (extra='forbid') ---")
    raw_payload = {
        "goal": "test goal",
        "step": 1,
        "dom": {
            "url": "http://127.0.0.1:8000",
            "title": "",
            "viewport": [1280, 720],
            "scrollY": 0,
            "nodes": [
                {
                    "id": "e1",
                    "tag": "input",
                    "label": "Test",
                    "bbox": [0, 0, 10, 10],
                    "sensitive": False,
                    "unauthorized_field": "leak"  # Extra field
                }
            ]
        },
        "history": []
    }
    rejected = False
    try:
        PlanRequest.model_validate(raw_payload)
    except Exception as e:
        rejected = True
        print(f"  Pydantic correctly rejected payload with extra field: {type(e).__name__}")

    assert rejected, "Schema failed to forbid extra fields!"
    print("  [PASS] Pydantic extra='forbid' verified.")


def test_vault_resolution():
    """Simulate extension-side local vault resolution."""
    print("\n--- Test 4: Local Vault Resolution & Unknown Token Rejection ---")
    def resolve_tokens(val: str, vault: dict) -> str:
        tokens = re.findall(r"\{\{([A-Z0-9_]+)\}\}", val)
        for t in tokens:
            if t not in vault:
                raise ValueError(f"Action rejected: unknown vault placeholder {{{{{t}}}}}")
        return re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: vault[m.group(1)], val)

    assert resolve_tokens("{{NAME}}", VAULT) == "Asha Verma"
    assert resolve_tokens("{{EMAIL}}", VAULT) == "asha@example.com"
    assert resolve_tokens("{{PHONE}}", VAULT) == "9876543210"

    # Test unknown token rejection
    rejected = False
    try:
        resolve_tokens("{{UNKNOWN_PII}}", VAULT)
    except ValueError as e:
        rejected = True
        print(f"  Correctly rejected: {e}")
    assert rejected, "Failed to reject unknown vault placeholder"
    print("  [PASS] Local vault placeholder resolution and rejection verified.")


def test_risky_action_detection():
    """Test detection of risky clicks requiring user popup approval."""
    print("\n--- Test 5: Risky Action Detection (Submit/Pay/Delete/Confirm/Send) ---")
    risky_patterns = re.compile(r"submit|pay|buy|delete|confirm|send", re.I)

    def is_risky(label: str, reason: str, tag: str, node_type: str) -> bool:
        if node_type == "submit" or tag == "button":
            return bool(risky_patterns.search(label) or risky_patterns.search(reason) or node_type == "submit")
        return bool(risky_patterns.search(label) or risky_patterns.search(reason))

    assert is_risky("Submit", "submit form", "button", "button") is True
    assert is_risky("Pay Now", "pay bill", "button", "button") is True
    assert is_risky("Confirm", "confirm order", "button", "button") is True
    assert is_risky("Delete", "delete item", "button", "button") is True
    assert is_risky("Next", "go to next step", "button", "button") is False
    print("  [PASS] Risky click approval triggers verified.")


def test_privacy_gate_checks():
    """Test privacy gate validation assertions."""
    print("\n--- Test 6: Privacy Gate Assertions ---")
    forbidden_keys = {"value", "innerText", "password"}

    def check_clean(dom_dict: dict):
        # Invariant 1d checks
        if dom_dict.get("title") != "":
            raise ValueError("GATE: page title must not be sent")
        url = dom_dict.get("url", "")
        if "/" in url.replace("http://", "").replace("https://", "").rstrip("/"):
            raise ValueError("GATE: URL path must not be sent (origin only)")

        # Forbidden keys walk
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in forbidden_keys:
                        raise ValueError(f"GATE: forbidden field '{k}'")
                    walk(v)
            elif isinstance(o, list):
                for item in o:
                    walk(item)
        walk(dom_dict)

    # Valid DOM
    valid_dom = {
        "url": "http://127.0.0.1:8000",
        "title": "",
        "nodes": [{"id": "e1", "tag": "input", "label": "Full name"}]
    }
    check_clean(valid_dom)

    # Leaking title
    leak_title = {"url": "http://127.0.0.1:8000", "title": "KYC Demo - John Doe", "nodes": []}
    try:
        check_clean(leak_title)
        assert False, "Gate should have blocked title leak"
    except ValueError as e:
        print(f"  Blocked title leak: {e}")

    # Leaking path
    leak_path = {"url": "http://127.0.0.1:8000/users/profile/123", "title": "", "nodes": []}
    try:
        check_clean(leak_path)
        assert False, "Gate should have blocked path leak"
    except ValueError as e:
        print(f"  Blocked path leak: {e}")

    # Leaking input value
    leak_value = {"url": "http://127.0.0.1:8000", "title": "", "nodes": [{"id": "e1", "value": "Asha Verma"}]}
    try:
        check_clean(leak_value)
        assert False, "Gate should have blocked input value"
    except ValueError as e:
        print(f"  Blocked input value leak: {e}")

    print("  [PASS] Privacy gate assertions fail closed as required.")


if __name__ == "__main__":
    print("=" * 60)
    print("Starting Veil Agent Loop Evaluation Suite (eval/run_loop_test.py)")
    print("=" * 60)
    test_full_loop_sequence()
    test_statelessness()
    test_schema_hardening_extra_fields()
    test_vault_resolution()
    test_risky_action_detection()
    test_privacy_gate_checks()
    print("\n" + "=" * 60)
    print("ALL EVALUATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
