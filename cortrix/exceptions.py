"""cortrix/exceptions.py — Cortrix SDK Exceptions."""

class CortrixError(Exception):
    """Base exception for Cortrix SDK errors."""
    pass

class PolicyViolation(CortrixError):
    """Raised when Cortrix blocks a request due to a policy violation."""
    def __init__(self, reason: str, decision: str = "DENY", event_id: str = None):
        self.reason = reason
        self.decision = decision
        self.event_id = event_id
        super().__init__(f"[{decision}] {reason}")
