"""
cortrix/client.py — Cortrix Security SDK Client.

Manages agent registration, Ed25519 key lifecycle, and automatic
request signing. Private keys are encrypted at rest using AES-256
derived from the API key — NEVER stored or transmitted to Cortrix servers.

Usage:
    from cortrix import CortrixClient

    client = CortrixClient(
        api_key="ctx_...",
        workspace_id="your-workspace-uuid",
        agent_id="hr-assistant",
    )

    # Register once — private key encrypted and saved locally
    client.register_agent(model_id="claude-sonnet-4.5")

    # Every scan is automatically signed
    result = client.scan("Customer John wants a refund")
    # result["decision"] == "ALLOW"
    # Signature automatically verified server-side → "CERTIFIED" in Dashboard

    # Verify any event's cryptographic proof
    cert = client.verify_event(result["event_id"])
    # cert["signature_valid"] == True
    # cert["chain_valid"] == True
    # cert["statement"] == "Agent hr-assistant ... Signature: VERIFIED. Chain integrity: INTACT."
"""
import hashlib
import base64
import os
import logging
import warnings
from pathlib import Path
from typing import Optional

import httpx
from cryptography.hazmat.primitives import serialization

from cortrix.keyring import save_key, load_key, delete_key, _key_path

logger = logging.getLogger("cortrix")


class CortrixClient:
    """
    Cortrix Security Client with automatic cryptographic signing.

    On registration, the backend generates an Ed25519 keypair:
      - Public key → stored in Cortrix DB (for verification)
      - Private key → returned ONCE → encrypted and saved to ~/.cortrix/keys/

    On every scan(), the SDK:
      1. Loads the private key from the encrypted keyring
      2. Signs SHA-256(prompt) with Ed25519
      3. Sends the signature + passport_id with the intercept request
      4. Backend verifies the signature → produces "CERTIFIED" evidence
    """

    def __init__(
        self,
        api_key: str,
        workspace_id: str,
        agent_id: str = "default-agent",
        endpoint: str = "https://api.cortrix.ai",
        key_dir: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the Cortrix client.

        Args:
            api_key: Your Cortrix API key (also used to encrypt local keyring)
            workspace_id: Your workspace UUID
            agent_id: Default agent identifier for scans
            endpoint: Cortrix API endpoint URL
            key_dir: Custom directory for encrypted key storage (default: ~/.cortrix/keys/)
            private_key_pem: Optional pre-loaded private key PEM (skips keyring)
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key
        self.workspace_id = workspace_id
        self.agent_id = agent_id
        self.endpoint = endpoint.rstrip("/")
        self.passport_id: Optional[str] = None
        self._key_dir = key_dir
        self._timeout = timeout

        # Private key: check explicit param → env var → encrypted keyring
        self._private_key_pem: Optional[str] = private_key_pem

        if not self._private_key_pem:
            env_key = os.environ.get("CORTRIX_PRIVATE_KEY")
            if env_key:
                self._private_key_pem = env_key
                logger.debug("Loaded private key from CORTRIX_PRIVATE_KEY env var")

        if not self._private_key_pem:
            try:
                loaded = load_key(self.api_key, self.agent_id, self._key_dir)
                if loaded:
                    self._private_key_pem = loaded
                    logger.debug(f"Loaded encrypted private key for agent '{self.agent_id}'")
            except ValueError as e:
                warnings.warn(str(e))

        # Load passport_id from env if available
        self.passport_id = os.environ.get("CORTRIX_PASSPORT_ID")

        # HTTP client
        self._http = httpx.Client(
            base_url=self.endpoint,
            headers={
                "X-Cortex-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )

    def register_agent(
        self,
        agent_id: Optional[str] = None,
        display_name: Optional[str] = None,
        model_id: str = "unknown",
        model_provider: str = "unknown",
        system_prompt_hash: Optional[str] = None,
    ) -> dict:
        """
        Register an agent and save the private key to the encrypted keyring.

        If the agent was previously registered, this rotates the keys:
        old key → status='rotated', new keypair generated.

        The private key is encrypted with your API key (HKDF + AES-256)
        and saved to ~/.cortrix/keys/{agent_id}.enc

        Returns registration info (WITHOUT the private key for safety).
        """
        aid = agent_id or self.agent_id
        self.agent_id = aid

        resp = self._http.post("/v1/agents/register", json={
            "agent_id": aid,
            "workspace_id": self.workspace_id,
            "display_name": display_name or aid,
            "model_id": model_id,
            "model_provider": model_provider,
            "system_prompt_hash": system_prompt_hash,
        })
        resp.raise_for_status()
        data = resp.json()

        # Save private key to encrypted local keyring
        private_key = data.get("private_key")
        if private_key:
            key_path = save_key(self.api_key, aid, private_key, self._key_dir)
            self._private_key_pem = private_key
            logger.info(f"Agent '{aid}' registered. Key encrypted at: {key_path}")

        self.passport_id = data.get("passport_id")

        # Return response WITHOUT private key (security hygiene)
        safe_response = {k: v for k, v in data.items() if k != "private_key"}
        safe_response["key_saved_to"] = str(_key_path(aid, self._key_dir))
        safe_response["signing_enabled"] = self._private_key_pem is not None
        return safe_response

    def scan(
        self,
        prompt: str,
        direction: str = "inbound",
        target_endpoint: str = "/v1/chat/completions",
        model_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict:
        """
        Scan a prompt through Cortrix with automatic Ed25519 signing.

        If a private key is available (from registration or keyring),
        the request is cryptographically signed. The backend verifies
        the signature using the stored public key.

        The resulting audit event will show:
          Signature: VERIFIED
          Chain Integrity: INTACT
          ✓ VALIDATED

        Args:
            prompt: The text to scan (user prompt or LLM response)
            direction: "inbound" (user→LLM) or "outbound" (LLM→user)
            target_endpoint: The API endpoint being called
            model_id: LLM model identifier
            agent_id: Override agent_id for this scan

        Returns:
            dict with decision, event_id, blocked, redacted_prompt, etc.
        """
        aid = agent_id or self.agent_id

        body = {
            "prompt": prompt,
            "agent_id": aid,
            "workspace_id": self.workspace_id,
            "direction": direction,
            "target_endpoint": target_endpoint,
            "model_id": model_id or "unknown",
        }

        # Automatic Ed25519 signing
        if self._private_key_pem and self.passport_id:
            prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            signature = self._sign(prompt_hash)
            if signature:
                body["passport_id"] = self.passport_id
                body["request_signature"] = signature
                logger.debug(f"Request signed with passport {self.passport_id[:8]}...")
        elif not self._private_key_pem:
            logger.debug("No private key available — request will be unsigned")
        elif not self.passport_id:
            logger.debug("No passport_id — request will be unsigned")

        path = "/v1/intercept/response" if direction == "outbound" else "/v1/intercept"
        resp = self._http.post(path, json=body)
        resp.raise_for_status()
        return resp.json()

    def verify_event(self, event_id: str) -> dict:
        """
        Retrieve the cryptographic verification certificate for an audit event.

        Returns the same VerificationCertificate shown in the Dashboard UI:
          {
            "event_id": "...",
            "signature_valid": true,
            "chain_valid": true,
            "fingerprint": "094b4c38...",
            "statement": "Agent hr-assistant running claude-sonnet-4.5
                          made decision ALLOW at 2026-04-22 13:00:38 UTC.
                          Signature: VERIFIED. Chain integrity: INTACT."
          }
        """
        resp = self._http.get(f"/v1/audit/verify/{event_id}")
        resp.raise_for_status()
        return resp.json()

    def rotate_keys(self, agent_id: Optional[str] = None) -> dict:
        """
        Rotate keys by re-registering (old key → status='rotated').

        Previous audit events will show "VERIFIED (Rotated Key)".
        New events will use the fresh keypair.
        """
        return self.register_agent(agent_id or self.agent_id)

    def list_agents(self) -> list[dict]:
        """Fetch all agents for this workspace."""
        resp = self._http.get(f"/v1/agents?workspace_id={self.workspace_id}")
        resp.raise_for_status()
        return resp.json()

    # ── Private Key Operations ─────────────────────────

    def _sign(self, payload: str) -> Optional[str]:
        """Sign a payload string with the local Ed25519 private key."""
        try:
            private_key = serialization.load_pem_private_key(
                self._private_key_pem.encode("utf-8"),
                password=None,
            )
            signature = private_key.sign(payload.encode("utf-8"))
            return base64.b64encode(signature).decode("utf-8")
        except Exception as e:
            warnings.warn(f"Cortrix: Signing failed: {e}. Request will be sent unsigned.")
            return None

    @property
    def has_signing_key(self) -> bool:
        """Check if a private key is available for signing."""
        return self._private_key_pem is not None

    @property
    def key_path(self) -> str:
        """Path to the encrypted key file for the current agent."""
        return str(_key_path(self.agent_id, self._key_dir))

    def close(self):
        """Close the HTTP client and clear sensitive data from memory."""
        self._http.close()
        self._private_key_pem = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return (
            f"CortrixClient(agent_id='{self.agent_id}', "
            f"signing={'enabled' if self.has_signing_key else 'disabled'}, "
            f"passport={self.passport_id[:8] + '...' if self.passport_id else 'none'})"
        )
