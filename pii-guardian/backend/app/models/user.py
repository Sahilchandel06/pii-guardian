from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.database.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(160), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user", index=True)  # admin or user
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
