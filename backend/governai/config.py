"""Runtime configuration. Secrets come from the environment; for local development
they are otherwise generated once into a 0600 file and never committed."""
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _local_secrets(data_dir: Path) -> dict:
    path = data_dir / "secrets.json"
    if path.exists():
        return json.loads(path.read_text())
    values = {"jwt_secret": secrets.token_urlsafe(48), "fernet_key": Fernet.generate_key().decode()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(values, handle)
    return values


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("GOVERNAI_DATA_DIR", BACKEND_DIR / ".data")))
    portal_url: str = field(default_factory=lambda: os.environ.get("GOVERNAI_PORTAL_URL", "http://localhost:8100").rstrip("/"))
    openai_api_key: str | None = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY") or None)
    openai_model: str = field(default_factory=lambda: os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
    # Uses Playwright's own Chromium when empty; "chrome" uses the installed browser.
    browser_channel: str | None = field(default_factory=lambda: os.environ.get("GOVERNAI_BROWSER_CHANNEL") or None)
    demo_password: str = field(default_factory=lambda: os.environ.get("GOVERNAI_DEMO_PASSWORD", "demo"))
    max_workers: int = field(default_factory=lambda: _env_int("GOVERNAI_MAX_WORKERS", 4))
    max_tool_calls: int = field(default_factory=lambda: _env_int("GOVERNAI_MAX_TOOL_CALLS", 40))
    max_attempts: int = field(default_factory=lambda: _env_int("GOVERNAI_MAX_ATTEMPTS", 3))
    retry_backoff_seconds: float = 0.4
    browser_timeout_ms: int = 8000
    token_ttl_minutes: int = 12 * 60

    def __post_init__(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        local = _local_secrets(self.data_dir)
        self.jwt_secret = os.environ.get("GOVERNAI_JWT_SECRET", local["jwt_secret"])
        self.fernet_key = os.environ.get("GOVERNAI_FERNET_KEY", local["fernet_key"])
        self.database_url = os.environ.get("GOVERNAI_DATABASE_URL", f"sqlite:///{self.data_dir / 'governai.db'}")

    @property
    def portal_host(self) -> str:
        return urlsplit(self.portal_url).netloc


settings = Settings()
