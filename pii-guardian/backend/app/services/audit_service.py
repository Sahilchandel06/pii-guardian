from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def write_audit_log(db: Session, user_id: int, action: str, details: str) -> None:
    db.add(AuditLog(user_id=user_id, action=action, details=details))
    db.commit()
