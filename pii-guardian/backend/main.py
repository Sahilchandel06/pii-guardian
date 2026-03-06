from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.database.db import Base, engine
from app.models.audit import AuditLog  # noqa: F401
from app.models.file import FileRecord  # noqa: F401
from app.models.user import User  # noqa: F401
from app.routes.audit_routes import router as audit_router
from app.routes.auth_routes import router as auth_router
from app.routes.file_routes import router as file_router

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

app = FastAPI(title="PII Guardian", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    return {"status": "ok", "service": "pii-guardian"}


app.include_router(auth_router)
app.include_router(file_router)
app.include_router(audit_router)
