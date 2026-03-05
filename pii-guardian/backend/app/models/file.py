from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.database.db import Base


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(120), nullable=True)
    original_path = Column(String(500), nullable=False)
    sanitized_path = Column(String(500), nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    upload_time = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    sanitization_mode = Column(String(20), nullable=False, default="mask")
    pii_count = Column(Integer, nullable=False, default=0)
    detection_summary = Column(Text, nullable=True)
