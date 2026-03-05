from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=6, max_length=64)
    role: Literal["admin", "user"] = "user"
    admin_token: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Literal["admin", "user"]


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: Literal["admin", "user"]
    created_at: datetime


class UpdateUserRoleRequest(BaseModel):
    role: Literal["admin", "user"]
