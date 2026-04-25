"""cortrix/core.py — Singleton engine for Cortrix SDK decorators."""
import os
import httpx
import hashlib
import base64
import logging
from typing import Optional

from cortrix.keyring import load_key

logger = logging.getLogger("cortrix")

class Cortrix:
    """Singleton engine that handles scanning and signing for the @guard decorator."""

    _instance = None

    def __new__(cls, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, api_key: str = None, endpoint: str = None, workspace_id: str = None, timeout: float = 10.0):
        if self._initialized:
            return
            
        self.api_key = api_key or os.environ.get("CORTRIX_API_KEY", "")
        self.endpoint = (endpoint or os.environ.get("CORTRIX_ENDPOINT", "https://api.cortrix.ai")).rstrip("/")
        self.workspace_id = workspace_id or os.environ.get("CORTRIX_WORKSPACE_ID", "")
        self._timeout = timeout
        
        self._http = httpx.Client(
            base_url=self.endpoint,
            headers={"X-Cortex-API-Key": self.api_key, "Content-Type": "application/json"},
            timeout=self._timeout,
        )
        self._passport_id = os.environ.get("CORTRIX_PASSPORT_ID")
        self._initialized = True

    def scan(self, text: str, direction: str = "inbound", agent_id: str = "default", model_id: str = "unknown") -> dict:
        """Send text to Cortrix for scanning. Returns decision + safe text."""
        body = {
            "prompt": text, 
            "agent_id": agent_id, 
            "direction": direction,
            "workspace_id": self.workspace_id,
            "model_id": model_id,
            "target_endpoint": "/v1/chat/completions" # Default
        }
        
        # Load private key just-in-time for this agent
        private_key = None
        try:
            private_key = load_key(self.api_key, agent_id)
        except Exception:
            pass

        # Sign if we have keys
        if private_key and self._passport_id:
            sig = self._sign(private_key, hashlib.sha256(text.encode("utf-8")).hexdigest())
            if sig:
                body["passport_id"] = self._passport_id
                body["request_signature"] = sig
                
        try:
            r = self._http.post("/v1/intercept" if direction == "inbound" else "/v1/intercept/response", json=body)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            # FAIL OPEN — never block the developer's app if Cortrix is down
            logger.warning(f"Cortrix scan failed (fail-open): {e}")
            return {"blocked": False, "decision": "ALLOW", "redacted_prompt": text}

    def _sign(self, private_key_pem: str, payload: str) -> Optional[str]:
        from cryptography.hazmat.primitives import serialization
        try:
            key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            signature = key.sign(payload.encode("utf-8"))
            return base64.b64encode(signature).decode("utf-8")
        except Exception as e:
            logger.warning(f"Cortrix: Signing failed: {e}")
            return None
