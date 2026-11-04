"""Tests run the real stack: a temporary database, the real engine, a real browser,
and the portal served over HTTP from its own server thread."""
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


PORT = _free_port()
os.environ["GOVERNAI_DATA_DIR"] = tempfile.mkdtemp(prefix="governai-test-")
os.environ["GOVERNAI_PORTAL_URL"] = f"http://localhost:{PORT}"
os.environ["GOVERNAI_DEMO_PASSWORD"] = "test-password"
os.environ.pop("OPENAI_API_KEY", None)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "portal"))


@pytest.fixture(scope="session", autouse=True)
def portal():
    import uvicorn
    from app import app as portal_app

    server = uvicorn.Server(uvicorn.Config(portal_app, host="127.0.0.1", port=PORT, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def client(portal):
    from fastapi.testclient import TestClient
    from governai.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def tokens(client):
    result = {}
    for username in ("student", "approver", "admin", "auditor"):
        response = client.post("/auth/login", json={"username": username, "password": "test-password"})
        assert response.status_code == 200
        result[username] = {"Authorization": f"Bearer {response.json()['token']}"}
    return result
