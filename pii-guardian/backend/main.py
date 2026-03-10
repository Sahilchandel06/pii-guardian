import os
import time
import asyncio
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.database.db import Base, engine
from app.database.migrations import run_startup_migrations
from app.models.audit import AuditLog  # noqa: F401
from app.models.file import FileRecord  # noqa: F401
from app.models.user import User  # noqa: F401
from app.routes.audit_routes import router as audit_router
from app.routes.auth_routes import router as auth_router
from app.routes.file_routes import router as file_router

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

app = FastAPI(title="PII Guardian", version="1.0.0")

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
CORS_ALLOW_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "120"))
_request_hits: dict[str, deque[float]] = defaultdict(deque)
_request_hits_lock = Lock()


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

Base.metadata.create_all(bind=engine)
run_startup_migrations()


def _is_weak_secret(value: str) -> bool:
    weak_values = {"", "supersecret-change-me", "change-this-secret", "changeme"}
    return value.strip().lower() in weak_values or len(value.strip()) < 24


def _validate_security_config() -> None:
    jwt_secret = os.getenv("JWT_SECRET_KEY", "")
    file_key = os.getenv("FILE_ENCRYPTION_KEY", "")
    master_wrap_key = os.getenv("FILE_MASTER_KEY", "")
    if APP_ENV == "production":
        if _is_weak_secret(jwt_secret):
            raise RuntimeError("JWT_SECRET_KEY must be strong in production.")
        if not (file_key or master_wrap_key):
            raise RuntimeError("Set FILE_MASTER_KEY (preferred) or FILE_ENCRYPTION_KEY in production.")


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _request_hits_lock:
        bucket = _request_hits[client_ip]
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"Rate limit exceeded: max {RATE_LIMIT_REQUESTS} requests/"
                        f"{RATE_LIMIT_WINDOW_SECONDS}s per client."
                    )
                },
            )
        bucket.append(now)
    try:
        response = await call_next(request)
    except asyncio.CancelledError:
        # Client disconnected while a long-running request was in progress.
        return JSONResponse(status_code=499, content={"detail": "Request cancelled by client"})
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "pii-guardian",
        "environment": APP_ENV,
    }


app.include_router(auth_router)
app.include_router(file_router)
app.include_router(audit_router)

_validate_security_config()


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_enabled = os.getenv("UVICORN_RELOAD", "false").lower() == "true"
    ssl_certfile = os.getenv("SSL_CERTFILE")
    ssl_keyfile = os.getenv("SSL_KEYFILE")

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload_enabled,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
