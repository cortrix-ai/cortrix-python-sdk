"""
cortrix/guard.py — Zero-code-change scan context manager.

Wraps any prompt scan with automatic signing and provides a clean
interface for checking the result.

Usage:
    from cortrix import CortrixClient, CortrixGuard

    client = CortrixClient(api_key="ctx_...", workspace_id="...")

    with CortrixGuard(client, prompt="Refund for john@acme.com") as guard:
        if guard.allowed:
            response = llm.complete(guard.safe_prompt)
        else:
            print(f"Blocked: {guard.reason}")

    # guard.event_id can be used to retrieve the verification certificate
    cert = client.verify_event(guard.event_id)
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class GuardResult:
    """Result of a Cortrix security scan."""
    allowed: bool
    safe_prompt: str
    decision: str
    event_id: str
    overhead_ms: int
    reason: Optional[str] = None
    blocked: bool = False
    pii_count: int = 0
    injection_score: float = 0.0
    signed: bool = False
    raw: dict = field(default_factory=dict)


@contextmanager
def CortrixGuard(
    client,
    prompt: str,
    direction: str = "inbound",
    target_endpoint: str = "/v1/chat/completions",
    model_id: Optional[str] = None,
    agent_id: Optional[str] = None,
):
    """
    Context manager that scans a prompt with automatic signing.

    Yields a GuardResult with the scan decision and safe prompt.
    """
    result = client.scan(
        prompt,
        direction=direction,
        target_endpoint=target_endpoint,
        model_id=model_id,
        agent_id=agent_id,
    )

    is_blocked = result.get("blocked", False)
    pii_detected = result.get("pii_detected", [])

    yield GuardResult(
        allowed=not is_blocked,
        blocked=is_blocked,
        safe_prompt=result.get("redacted_prompt", prompt) if not is_blocked else prompt,
        decision=result.get("decision", "ALLOW"),
        event_id=result.get("event_id", ""),
        overhead_ms=result.get("overhead_ms", 0),
        reason=result.get("reason"),
        pii_count=len(pii_detected) if isinstance(pii_detected, list) else 0,
        injection_score=result.get("injection_score", 0.0),
        signed=result.get("request_signature") is not None,
        raw=result,
    )
