from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from app.database.db import Base


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(120), nullable=True)
    original_path = Column(String(500), nullable=False)
    sanitized_path = Column(String(500), nullable=True, default="")
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    upload_time = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    sanitization_mode = Column(String(20), nullable=False, default="mask")
    pii_count = Column(Integer, nullable=False, default=0)
    detection_summary = Column(Text, nullable=True)
    encrypted_dek = Column(Text, nullable=True)
    encryption_version = Column(String(30), nullable=True, default="legacy_fernet")
    file_sha256 = Column(String(64), nullable=True)
    cipher_sha256 = Column(String(64), nullable=True)
    retention_expires_at = Column(DateTime, nullable=True, index=True)
    legal_hold = Column(Boolean, nullable=False, default=False, index=True)
