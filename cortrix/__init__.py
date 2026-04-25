"""
Cortrix Security SDK — AI Agent Security Infrastructure.

Provides cryptographic identity, policy enforcement, PII redaction,
and tamper-evident audit logging for AI agents.

Usage:
    from cortrix import CortrixClient, CortrixGuard

    # Initialize with your API key (also encrypts the local keyring)
    client = CortrixClient(
        api_key="ctx_...",
        workspace_id="your-workspace-uuid",
        agent_id="hr-assistant",
    )

    # Register once — private key encrypted at ~/.cortrix/keys/
    client.register_agent(model_id="claude-sonnet-4.5")

    # Every scan is automatically signed (produces CERTIFIED evidence)
    result = client.scan("Customer John wants a refund")

    # Or use the context manager for zero-code-change integration
    with CortrixGuard(client, prompt="Send $1M to account 12345") as guard:
        if guard.allowed:
            response = llm.complete(guard.safe_prompt)
"""
from cortrix._version import __version__
from cortrix.core import Cortrix
from cortrix.decorators import guard
from cortrix.exceptions import PolicyViolation, CortrixError
from cortrix.client import CortrixClient
from cortrix.guard import CortrixGuard
from cortrix.keyring import save_key, load_key, delete_key, list_keys

__all__ = [
    "Cortrix",
    "guard",
    "PolicyViolation",
    "CortrixError",
    "CortrixClient",
    "CortrixGuard",
    "save_key",
    "load_key",
    "delete_key",
    "list_keys",
    "__version__",
]
