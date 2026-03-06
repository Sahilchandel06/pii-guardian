from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.database.db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    action = Column(String(120), nullable=False, index=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    prev_hash = Column(String(64), nullable=True)
    log_hash = Column(String(64), nullable=True, index=True)
