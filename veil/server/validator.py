"""Server Defense-in-Depth Planning Checks (Task 6).
Validates planner output on the server before sending to client.
Invariants:
- Server output remains UNTRUSTED: the client always validates everything independently (Invariant 1).
- Server defense-in-depth rejects responses targeting nonexistent node IDs or sensitive/password/card nodes.
"""
from typing import Optional
from schema import ActionResponse, FailResponse, PlanRequest, PlanResponse


def validate_planned_action(response: PlanResponse, req: PlanRequest) -> PlanResponse:
    """Validate planned action against the request DOM nodes.
    Defense in depth: rejects invalid node IDs and sensitive targets.
    """
    if not isinstance(response, ActionResponse):
        # answer, ask_user, done, fail are safe from DOM node targeting
        return response

    if response.target_id:
        # 1. Target ID must exist in request DOM nodes
        node_map = {n.id: n for n in req.dom.nodes}
        target_node = node_map.get(response.target_id)
        if not target_node:
            # Check if visual_only node allowed in fusion (e.g., vo1, vo2)
            if not response.target_id.startswith("vo"):
                return FailResponse(
                    reason=f"Server guard: target node '{response.target_id}' does not exist in request DOM"
                )

        if target_node:
            # 2. Reject targeting sensitive / password / card nodes
            if target_node.sensitive:
                return FailResponse(
                    reason=f"Server guard: target node '{response.target_id}' is marked sensitive"
                )

            tag = (target_node.tag or "").lower()
            input_type = (target_node.type or "").lower()
            if input_type in ("password", "otp"):
                return FailResponse(
                    reason=f"Server guard: target node '{response.target_id}' is password/otp field"
                )

            if target_node.pii and any(p in ("card", "aadhaar", "password") for p in target_node.pii):
                return FailResponse(
                    reason=f"Server guard: target node '{response.target_id}' has sensitive PII"
                )

    if response.coords:
        x, y = response.coords
        vw, vh = req.dom.viewport
        if x < 0 or y < 0 or x > vw or y > vh:
            return FailResponse(
                reason=f"Server guard: coords [{x}, {y}] outside viewport [{vw}, {vh}]"
            )

    return response
