import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User
from app.schemas.auth_schema import (
    LoginRequest,
    SignupRequest,
    TokenResponse,
    UpdateUserRoleRequest,
)
from app.services.audit_service import write_audit_log
from app.utils.security import (
    create_access_token,
    get_current_admin,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))


@router.post("/signup")
def signup(data: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == data.username) | (User.email == data.email)).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")

    role = "user"
    if data.role == "admin":
        has_users = db.query(User).count() > 0
        allowed_bootstrap = not has_users
        admin_registration_token = os.getenv("ADMIN_REGISTRATION_TOKEN")
        valid_admin_token = admin_registration_token and data.admin_token == admin_registration_token
        if not (allowed_bootstrap or valid_admin_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin signup is restricted. Use ADMIN_REGISTRATION_TOKEN or bootstrap first user.",
            )
        role = "admin"

    user = User(
        username=data.username.strip(),
        email=data.email.strip().lower(),
        password_hash=hash_password(data.password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit_log(db, user.id, "SIGNUP", f"New user created with role={user.role}")

    return {"message": "User created successfully", "user_id": user.id, "role": user.role}


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    now = datetime.utcnow()
    if user.locked_until and user.locked_until > now:
        write_audit_log(
            db,
            user.id,
            "LOGIN_BLOCKED",
            f"Account locked until {user.locked_until.isoformat()}",
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account temporarily locked. Try again after {user.locked_until.isoformat()} UTC",
        )

    if not verify_password(data.password, user.password_hash):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOGIN_LOCK_MINUTES)
            user.failed_login_attempts = 0
            db.commit()
            write_audit_log(
                db,
                user.id,
                "LOGIN_LOCKOUT",
                f"Too many failed logins. Locked until {user.locked_until.isoformat()}",
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account temporarily locked. Try again after {user.locked_until.isoformat()} UTC",
            )
        db.commit()
        write_audit_log(
            db,
            user.id,
            "LOGIN_FAIL",
            f"Invalid password attempt count={user.failed_login_attempts}",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Reset lockout state on successful login.
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token = create_access_token({"user_id": user.id, "role": user.role})
    write_audit_log(db, user.id, "LOGIN", f"User {user.username} logged in")

    return TokenResponse(access_token=token, role=user.role)


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "created_at": current_user.created_at,
    }


@router.get("/users")
def list_users(admin_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    write_audit_log(db, admin_user.id, "USER_MANAGEMENT", "Viewed users list")
    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at,
        }
        for user in users
    ]


@router.put("/users/{user_id}/role")
def update_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.id == admin_user.id and payload.role != "admin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot demote your own admin account")

    target.role = payload.role
    db.commit()
    db.refresh(target)

    write_audit_log(db, admin_user.id, "USER_MANAGEMENT", f"Updated role for user_id={target.id} to {target.role}")
    return {"message": "Role updated", "user_id": target.id, "role": target.role}
