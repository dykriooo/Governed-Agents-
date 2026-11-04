"""Encryption at rest, password hashing, tokens, PII detection and redaction."""
import base64
import hashlib
import hmac
import json
import os
import re
from datetime import timedelta
from typing import Any

import jwt
from cryptography.fernet import Fernet

from .config import settings
from .db import utcnow

_fernet = Fernet(settings.fernet_key.encode())


def encrypt(value: Any) -> str:
    return _fernet.encrypt(json.dumps(value).encode()).decode()


def decrypt(token: str | None, default: Any = None) -> Any:
    return default if token is None else json.loads(_fernet.decrypt(token.encode()))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    salt_b64, digest_b64 = stored.split("$")
    digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=2**14, r=8, p=1)
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


def create_token(user_id: str) -> str:
    claims = {"sub": user_id, "exp": utcnow() + timedelta(minutes=settings.token_ttl_minutes)}
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


def read_token(token: str) -> str | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        return None


PII_PATTERNS = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "phone": re.compile(r"\+?\d[\d\s-]{8,}\d"),
    "date_of_birth": re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b"),
}
SENSITIVE_KEYS = {
    "full_name", "employee", "date_of_birth", "email", "phone", "national_id", "passport_number", "address", "text",
}
# Fields safe to keep across sessions. Memory is an allowlist so that a new
# sensitive field can never be retained by accident (data minimisation).
MEMORY_SAFE_KEYS = {"program", "intake", "previous_institution"}


def contains_pii(value: Any) -> bool:
    """True if a value holds personal data, judged by key name and by content."""
    if isinstance(value, dict):
        return any(
            (key in SENSITIVE_KEYS and bool(item)) or contains_pii(item) for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_pii(item) for item in value)
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in PII_PATTERNS.values())
    return False


def _scrub(text: str) -> str:
    for label, pattern in PII_PATTERNS.items():
        text = pattern.sub(f"[{label} redacted]", text)
    return text


def redact(value: Any) -> Any:
    """Copy of a value that is safe for logs and the audit trail."""
    if isinstance(value, dict):
        return {
            key: (f"[redacted {len(str(item))} chars]" if key in SENSITIVE_KEYS and item else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _scrub(value)
    return value


def mask_for_review(value: Any) -> Any:
    """What a human approver sees: real values, with government IDs masked."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in {"national_id", "passport_number"} and item:
                out[key] = f"•••• {str(item)[-4:]}"
            else:
                out[key] = mask_for_review(item)
        return out
    if isinstance(value, list):
        return [mask_for_review(item) for item in value]
    return value


def stable_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
