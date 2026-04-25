# Cortrix Security SDK

## Install

```bash
pip install cortrix
```

## Quick Start

The absolute fastest way to secure your AI application is using the provider-agnostic `@guard` decorator.

```python
import openai
from cortrix import guard

# 1. Apply the decorator. 
# Tell it which argument contains the prompt that needs scanning.
@guard(prompt_arg="user_input", agent_id="hr-assistant", model_id="gpt-4o")
def get_medical_advice(user_input: str) -> str:
    # Cortrix guarantees that `user_input` is safe and PII-redacted 
    # before this code block is ever executed.
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content

# Usage:
try:
    # If this contains a prompt injection, the decorator intercepts 
    # and raises a security exception before execution.
    result = get_medical_advice(user_input="My patient John Doe has cancer.")
    print(result)
except cortrix.PolicyViolation as e:
    print(f"Blocked: {e.reason}")
```

Cortrix automatically handles keys via environment variables:
```bash
export CORTRIX_API_KEY="ctx_your_api_key"
export CORTRIX_WORKSPACE_ID="your-workspace-uuid"
```

## Legacy Client (Explicit Registration)

If you need explicit control over key rotation and registration:

```python
from cortrix import CortrixClient, CortrixGuard

client = CortrixClient(api_key="ctx_...", workspace_id="...")

with CortrixGuard(client, prompt="Send $1M to account 12345") as guard:
    if guard.allowed:
        response = llm.complete(guard.safe_prompt)
    else:
        print(f"Blocked: {guard.reason}")
```

## Key Management

The SDK uses an **encrypted local keyring**:

- Private keys are encrypted with AES-256 (derived from your API key via HKDF)
- Stored at `~/.cortrix/keys/{agent_id}.enc`
- File permissions: 600 (owner read/write only)
- **Cortrix servers NEVER store or see your private key**

### Key Rotation

```python
# Rotate keys (old → status='rotated', new keypair generated)
client.rotate_keys()
# Previous audit events show "VERIFIED (Rotated Key)"
# New events use the fresh keypair
```

### Custom Key Directory

```python
# Via constructor
client = CortrixClient(api_key="...", key_dir="/secure/keys/")

# Via environment variable
export CORTRIX_KEY_DIR=/secure/keys/
```

## How Signing Works

```
1. Register → Backend generates Ed25519 keypair
2. Public key → stored in Cortrix DB (for verification)
3. Private key → returned ONCE → encrypted locally with AES-256
4. Every scan() → SDK signs SHA-256(prompt) with private key
5. Backend verifies signature → produces "CERTIFIED" evidence
6. Dashboard Inspector shows: Signature: VERIFIED ✓ VALIDATED
```
