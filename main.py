"""Vercel entrypoint that serves the frontend and the FastAPI backend."""

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"

# Vercel Functions can write to /tmp, while the deployed source bundle is read-only.
# Keep the local SQLite default unchanged for the separately-run development backend.
if os.getenv("VERCEL") and not os.getenv("PYGENIC_DB_PATH"):
    os.environ["PYGENIC_DB_PATH"] = "/tmp/trustnet-ai.db"

sys.path.insert(0, str(BACKEND_DIR))

from backend.main import app as backend_app  # noqa: E402
from fastapi import FastAPI  # noqa: E402


app = FastAPI(title="TrustNet-AI")
app.mount("/api", backend_app)
app.frontend(
    "/",
    directory=str(ROOT / "frontend" / "dist"),
    fallback="index.html",
)
