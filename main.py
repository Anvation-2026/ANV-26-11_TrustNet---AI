"""Vercel entrypoint that serves the frontend and the FastAPI backend."""

import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"
DIST_DIR = ROOT / "frontend" / "dist"

# Vercel Functions can write to /tmp, while the deployed source bundle is read-only.
# Keep the local SQLite default unchanged for the separately-run development backend.
if os.getenv("VERCEL") and not os.getenv("PYGENIC_DB_PATH"):
    os.environ["PYGENIC_DB_PATH"] = "/tmp/trustnet-ai.db"

sys.path.insert(0, str(BACKEND_DIR))

if os.getenv("VERCEL"):
    # Never let the deployed app open SQLite inside the read-only source bundle.
    import database  # noqa: E402

    for _attr in ("DB", "DB_PATH", "DATABASE_PATH"):
        _value = getattr(database, _attr, None)
        if isinstance(_value, (str, os.PathLike)) and str(_value).endswith(".db"):
            setattr(database, _attr, os.environ["PYGENIC_DB_PATH"])

from backend.main import app as backend_app  # noqa: E402

app = FastAPI(title="TrustNet-AI")
app.mount("/api", backend_app)

if DIST_DIR.is_dir():
    app.frontend("/", directory=str(DIST_DIR), fallback="index.html")
else:
    # Keep the API available if the frontend build is missing.
    @app.get("/")
    def frontend_not_built() -> JSONResponse:
        return JSONResponse(
            {"detail": "Frontend build not found at frontend/dist. Run `npm run build` before starting."},
            status_code=503,
        )
