from sqlalchemy import inspect, text

from app.database.db import engine


def _column_exists(table_name: str, column_name: str) -> bool:
    inspector = inspect(engine)
    return any(col["name"] == column_name for col in inspector.get_columns(table_name))


def _add_column_if_missing(table_name: str, ddl: str, column_name: str) -> None:
    if _column_exists(table_name, column_name):
        return
    with engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))


def run_startup_migrations() -> None:
    # files table extensions
    _add_column_if_missing("files", "encrypted_dek TEXT", "encrypted_dek")
    _add_column_if_missing("files", "encryption_version VARCHAR(30) DEFAULT 'legacy_fernet'", "encryption_version")
    _add_column_if_missing("files", "file_sha256 VARCHAR(64)", "file_sha256")
    _add_column_if_missing("files", "cipher_sha256 VARCHAR(64)", "cipher_sha256")
    _add_column_if_missing("files", "retention_expires_at TIMESTAMP", "retention_expires_at")
    _add_column_if_missing("files", "legal_hold BOOLEAN DEFAULT FALSE", "legal_hold")

    # audit_logs table extensions
    _add_column_if_missing("audit_logs", "prev_hash VARCHAR(64)", "prev_hash")
    _add_column_if_missing("audit_logs", "log_hash VARCHAR(64)", "log_hash")

    # users table hardening
    _add_column_if_missing("users", "failed_login_attempts INTEGER DEFAULT 0", "failed_login_attempts")
    _add_column_if_missing("users", "locked_until TIMESTAMP", "locked_until")
