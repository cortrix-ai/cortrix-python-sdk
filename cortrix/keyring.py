"""
cortrix/keyring.py — Encrypted keyring for Ed25519 private keys.

Private keys are encrypted at rest using AES-256 (Fernet) with a key
derived from the customer's API key via HKDF. This means:
  - Zero friction: no passphrase, no external service
  - Two-factor: attacker needs BOTH the .enc file AND the API key
  - Works everywhere: Docker, CI/CD, headless servers
"""
import os
import stat
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import base64

logger = logging.getLogger("cortrix.keyring")

DEFAULT_KEY_DIR = "~/.cortrix/keys"


def _derive_encryption_key(api_key: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible AES-256 key from the API key using HKDF.

    HKDF is appropriate here because API keys are high-entropy secrets
    (not user-chosen passwords), so we don't need Argon2/PBKDF2.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cortrix-keyring-v1",
    )
    derived = hkdf.derive(api_key.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _safe_agent_id(agent_id: str) -> str:
    """Sanitize agent_id for filesystem safety."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)


def _key_path(agent_id: str, key_dir: Optional[str] = None) -> Path:
    """Get the path to an agent's encrypted key file."""
    directory = Path(key_dir or os.environ.get("CORTRIX_KEY_DIR", DEFAULT_KEY_DIR)).expanduser()
    return directory / f"{_safe_agent_id(agent_id)}.enc"


def save_key(api_key: str, agent_id: str, private_key_pem: str, key_dir: Optional[str] = None) -> Path:
    """
    Encrypt and save a private key to the local keyring.

    File format: salt (16 bytes) + Fernet-encrypted PEM
    File permissions: 600 (owner read/write only)
    Directory permissions: 700 (owner only)
    """
    path = _key_path(agent_id, key_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Set directory permissions to owner-only (700)
    try:
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError:
        pass  # Windows may not support chmod

    # Generate random salt and derive encryption key
    salt = os.urandom(16)
    fernet_key = _derive_encryption_key(api_key, salt)
    encrypted = Fernet(fernet_key).encrypt(private_key_pem.encode("utf-8"))

    # Write: salt(16 bytes) + encrypted_data
    path.write_bytes(salt + encrypted)

    # Set file permissions to owner read/write only (600)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Windows may not support chmod

    logger.info(f"Private key encrypted and saved to {path}")
    return path


def load_key(api_key: str, agent_id: str, key_dir: Optional[str] = None) -> Optional[str]:
    """
    Load and decrypt a private key from the local keyring.

    Returns the PEM-encoded private key string, or None if not found.
    Raises ValueError if the API key is wrong (decryption fails).
    """
    path = _key_path(agent_id, key_dir)
    if not path.exists():
        return None

    data = path.read_bytes()
    if len(data) < 17:
        logger.warning(f"Corrupt key file: {path}")
        return None

    salt = data[:16]
    encrypted = data[16:]

    try:
        fernet_key = _derive_encryption_key(api_key, salt)
        decrypted = Fernet(fernet_key).decrypt(encrypted)
        return decrypted.decode("utf-8")
    except InvalidToken:
        raise ValueError(
            f"Failed to decrypt key for agent '{agent_id}'. "
            f"This usually means the API key has changed since the key was saved. "
            f"Re-register the agent to generate a new keypair."
        )


def delete_key(agent_id: str, key_dir: Optional[str] = None) -> bool:
    """Delete an agent's encrypted key file."""
    path = _key_path(agent_id, key_dir)
    if path.exists():
        path.unlink()
        logger.info(f"Deleted key file: {path}")
        return True
    return False


def list_keys(key_dir: Optional[str] = None) -> list[str]:
    """List all agent IDs that have stored keys."""
    directory = Path(key_dir or os.environ.get("CORTRIX_KEY_DIR", DEFAULT_KEY_DIR)).expanduser()
    if not directory.exists():
        return []
    return [f.stem for f in directory.glob("*.enc")]
