#!/usr/bin/env bash
# Starts the mock portal (8100), the API (8000) and the web app (3000). Ctrl-C stops all three.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
trap 'kill 0' EXIT

cd "$ROOT/backend"
.venv/bin/uvicorn app:app --app-dir ../portal --host 127.0.0.1 --port 8100 --log-level warning &
.venv/bin/uvicorn governai.main:app --host 127.0.0.1 --port 8000 --log-level warning &

cd "$ROOT/frontend"
npx next dev -p 3000 &
wait
