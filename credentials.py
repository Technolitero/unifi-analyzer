"""
Secure local credential storage for UniFi Analyzer.
Credentials are saved to ~/.unifi-analyzer/config.json.
Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
The encryption key is stored in ~/.unifi-analyzer/.key (permissions 0o600).
"""

import json
import os
import stat
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

CONFIG_DIR  = Path.home() / ".unifi-analyzer"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEY_FILE    = CONFIG_DIR / ".key"

# Fields that contain passwords and should be encrypted at rest
_PASSWORD_FIELDS = ("api_password", "udm_ssh_password", "device_ssh_password", "api_key")


def _restrict_file(path: Path):
    """Set file to owner-read/write only (best-effort on Windows)."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _get_or_create_key() -> bytes | None:
    """Return the Fernet key, creating it on first run."""
    if not _HAS_CRYPTO:
        return None
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    _restrict_file(KEY_FILE)
    return key


def _cipher():
    key = _get_or_create_key()
    if key is None:
        return None
    return Fernet(key)


def _encrypt(value: str) -> str:
    c = _cipher()
    if c is None or not value:
        return value
    return c.encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    c = _cipher()
    if c is None or not value:
        return value
    try:
        return c.decrypt(value.encode()).decode()
    except (InvalidToken, Exception):
        return ""


def load_config() -> dict:
    """Load and return saved credentials (passwords decrypted)."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        for field in _PASSWORD_FIELDS:
            if data.get(field):
                data[field] = _decrypt(data[field])
        return data
    except Exception:
        return {}


def save_config(data: dict):
    """Encrypt passwords and write config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    to_save = {k: v for k, v in data.items() if v is not None}
    for field in _PASSWORD_FIELDS:
        if to_save.get(field):
            to_save[field] = _encrypt(to_save[field])
    CONFIG_FILE.write_text(json.dumps(to_save, indent=2), encoding="utf-8")
    _restrict_file(CONFIG_FILE)
