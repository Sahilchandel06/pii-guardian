import hashlib
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.services.audit_service import write_audit_log
from app.utils.security import get_current_admin

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "timestamp": log.timestamp,
            "prev_hash": log.prev_hash,
            "log_hash": log.log_hash,
            "requested_by": admin_user.id,
        }
        for log in logs
    ]


@router.get("/verify-integrity")
def verify_audit_integrity(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    previous_hash = None

    for idx, log in enumerate(logs):
        digest_input = f"{log.user_id}|{log.action}|{log.details}|{log.timestamp.isoformat()}|{previous_hash or ''}"
        expected_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

        if log.prev_hash != previous_hash or log.log_hash != expected_hash:
            return {
                "ok": False,
                "broken_at_index": idx,
                "broken_log_id": log.id,
                "requested_by": admin_user.id,
            }
        previous_hash = log.log_hash

    return {
        "ok": True,
        "verified_count": len(logs),
        "last_hash": previous_hash,
        "requested_by": admin_user.id,
    }


@router.get("/logs/download")
def download_audit_logs(
    format: str = Query("csv", pattern="^(csv|json)$"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if format == "json":
        payload = [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "details": log.details,
                "timestamp": log.timestamp.isoformat(),
                "prev_hash": log.prev_hash,
                "log_hash": log.log_hash,
            }
            for log in logs
        ]
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        filename = f"audit_logs_{timestamp}.json"
        media_type = "application/json"
    else:
        import csv

        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["id", "user_id", "action", "details", "timestamp", "prev_hash", "log_hash"])
        for log in logs:
            writer.writerow(
                [
                    log.id,
                    log.user_id,
                    log.action,
                    log.details,
                    log.timestamp.isoformat(),
                    log.prev_hash or "",
                    log.log_hash,
                ]
            )
        data = output.getvalue().encode("utf-8")
        filename = f"audit_logs_{timestamp}.csv"
        media_type = "text/csv"

    write_audit_log(
        db,
        admin_user.id,
        "AUDIT_EXPORT",
        f"Downloaded audit logs format={format} count={len(logs)}",
    )

    return StreamingResponse(
        iter([data]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
