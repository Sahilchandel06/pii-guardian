import hashlib
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def write_audit_log(db: Session, user_id: int, action: str, details: str) -> None:
    previous = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = previous.log_hash if previous else None
    ts = datetime.utcnow()
    digest_input = f"{user_id}|{action}|{details}|{ts.isoformat()}|{prev_hash or ''}"
    log_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            timestamp=ts,
            prev_hash=prev_hash,
            log_hash=log_hash,
        )
    )
    db.commit()
