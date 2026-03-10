import json
import io
import mimetypes
import os
import uuid
import math
import hashlib
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import requests

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.audit import AuditLog
from app.models.file import FileRecord
from app.models.user import User
from app.services.audit_service import write_audit_log
from app.services.file_parser import extract_text_from_file, is_supported_file, sanitize_file_preserving_format
from app.utils.security import get_current_admin, get_current_user, verify_password
from app.utils.storage_crypto import (
    decrypt_bytes,
    decrypt_file_payload,
    encrypt_file_payload,
    pack_envelope_ciphertext,
    sha256_hex,
    unpack_envelope_ciphertext,
)

router = APIRouter(prefix="/files", tags=["Files"])

BASE_UPLOAD_DIR = Path("secure_storage")
ORIGINAL_DIR = BASE_UPLOAD_DIR / "originals"
SANITIZED_CACHE_DIR = BASE_UPLOAD_DIR / "sanitized_cache"
SANITIZED_CACHE_VERSION = os.getenv("SANITIZED_CACHE_VERSION", "v2")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
ORIGINAL_RETENTION_DAYS = int(os.getenv("ORIGINAL_RETENTION_DAYS", "30"))
STEPUP_REQUIRED_FOR_RAW_DOWNLOAD = os.getenv("STEPUP_REQUIRED_FOR_RAW_DOWNLOAD", "true").lower() == "true"
BACKUP_STEPUP_REQUIRED = os.getenv("BACKUP_STEPUP_REQUIRED", "true").lower() == "true"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_TIMEOUT_SECONDS = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "12"))
VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() == "true" and bool(VIRUSTOTAL_API_KEY)
VIRUSTOTAL_BLOCK_UNKNOWN = os.getenv("VIRUSTOTAL_BLOCK_UNKNOWN", "false").lower() == "true"
ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)
SANITIZED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
BLOCKED_BINARY_SIGNATURES = (
    b"MZ",  # Windows PE executables
    b"\x7fELF",  # ELF binaries
    b"\xcf\xfa\xed\xfe",  # Mach-O (32-bit)
    b"\xfe\xed\xfa\xcf",  # Mach-O (64-bit)
)
EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
RISK_ENTITY_WEIGHTS: dict[str, float] = {
    "IN_AADHAAR": 10.0,
    "CREDIT_CARD": 10.0,
    "BANK_ACCOUNT": 9.0,
    "PASSPORT_NUMBER": 8.0,
    "IN_PAN": 8.0,
    "FINGERPRINT_TEMPLATE": 8.0,
    "FACE_TEMPLATE": 8.0,
    "IFSC_CODE": 6.0,
    "DATE_OF_BIRTH": 6.0,
    "EMAIL_ADDRESS": 5.0,
    "PHONE_NUMBER": 5.0,
    "IN_ADDRESS": 5.0,
    "UPI_ID": 5.0,
    "DEVICE_ID": 4.0,
    "IP_ADDRESS": 3.0,
    "PERSON_NAME": 2.0,
    "BANK_NAME": 2.0,
}


def _save_bytes(path: Path, data: bytes) -> None:
    with open(path, "wb") as outfile:
        outfile.write(data)


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as infile:
        return infile.read()


def _get_file_or_404(db: Session, file_id: int) -> FileRecord:
    item = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return item


def _ensure_user_can_access_file(current_user: User, item: FileRecord) -> None:
    if current_user.role == "admin":
        return
    if item.uploaded_by != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this file")


def _effective_mode(item: FileRecord) -> str:
    ext = Path(item.filename).suffix.lower()
    if ext in {".pdf", ".png", ".jpg", ".jpeg"}:
        return "redact"
    return item.sanitization_mode or "mask"


def _read_original_verified(item: FileRecord) -> bytes:
    stored = _read_bytes(item.original_path)

    parsed = unpack_envelope_ciphertext(stored)
    if parsed and item.encrypted_dek:
        data_nonce_b64, wrap_nonce_b64, cipher_bytes = parsed

        if item.cipher_sha256:
            actual_cipher_hash = sha256_hex(cipher_bytes)
            if actual_cipher_hash != item.cipher_sha256:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ciphertext integrity verification failed")

        plain = decrypt_file_payload(
            cipher_bytes=cipher_bytes,
            encrypted_dek_b64=item.encrypted_dek,
            data_nonce_b64=data_nonce_b64,
            wrap_nonce_b64=wrap_nonce_b64,
        )

        if item.file_sha256:
            actual_plain_hash = sha256_hex(plain)
            if actual_plain_hash != item.file_sha256:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File integrity verification failed")
        return plain

    # Backward compatibility for legacy Fernet records.
    plain = decrypt_bytes(stored)
    if item.file_sha256:
        actual_plain_hash = sha256_hex(plain)
        if actual_plain_hash != item.file_sha256:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File integrity verification failed")
    return plain


def _cache_paths(item: FileRecord) -> tuple[Path, Path]:
    mode = _effective_mode(item)
    file_hash = item.file_sha256 or "nohash"
    key_raw = f"{SANITIZED_CACHE_VERSION}:{item.id}:{mode}:{file_hash}:{item.filename}"
    key = hashlib.sha256(key_raw.encode("utf-8")).hexdigest()[:24]
    ext = Path(item.filename).suffix.lower() or ".bin"
    payload_path = SANITIZED_CACHE_DIR / f"{item.id}_{key}.sanitized{ext}"
    meta_path = SANITIZED_CACHE_DIR / f"{item.id}_{key}.meta.json"
    return payload_path, meta_path


def _try_read_cached_sanitized(item: FileRecord) -> dict | None:
    payload_path, meta_path = _cache_paths(item)
    if not (payload_path.exists() and meta_path.exists()):
        return None
    try:
        payload_bytes = _read_bytes(str(payload_path))
        meta = json.loads(_read_bytes(str(meta_path)).decode("utf-8"))
        return {
            "sanitized_text": str(meta.get("sanitized_text", "")),
            "sanitized_original_bytes": payload_bytes,
            "sanitized_original_ext": str(meta.get("sanitized_original_ext", Path(item.filename).suffix.lower() or ".txt")),
            "sanitized_original_media_type": str(meta.get("sanitized_original_media_type", "application/octet-stream")),
            "findings": meta.get("findings", []) or [],
            "summary": meta.get("summary", {}) or {},
            "parser": str(meta.get("parser", "cached")),
        }
    except Exception:
        return None


def _try_write_cached_sanitized(item: FileRecord, payload: dict) -> None:
    payload_path, meta_path = _cache_paths(item)
    try:
        _save_bytes(payload_path, payload["sanitized_original_bytes"])
        meta = {
            "sanitized_text": payload.get("sanitized_text", ""),
            "sanitized_original_ext": payload.get("sanitized_original_ext", Path(item.filename).suffix.lower() or ".txt"),
            "sanitized_original_media_type": payload.get("sanitized_original_media_type", "application/octet-stream"),
            "findings": payload.get("findings", []),
            "summary": payload.get("summary", {}),
            "parser": payload.get("parser", ""),
        }
        _save_bytes(meta_path, json.dumps(meta, ensure_ascii=False, default=str).encode("utf-8"))
    except Exception:
        # Cache is best-effort; request should still succeed.
        return


def _build_sanitized_payload(item: FileRecord) -> dict:
    cached = _try_read_cached_sanitized(item)
    if cached is not None:
        return cached

    raw_bytes = _read_original_verified(item)
    mode = _effective_mode(item)
    try:
        payload = sanitize_file_preserving_format(item.filename, raw_bytes, mode=mode)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to sanitize file on-demand: {exc}",
        ) from exc
    _try_write_cached_sanitized(item, payload)
    return payload


def _update_detection_metadata(db: Session, item: FileRecord, payload: dict) -> None:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    pii_count = len(findings)
    expected_summary = json.dumps(summary)

    if item.pii_count == pii_count and (item.detection_summary or "") == expected_summary:
        return

    item.pii_count = pii_count
    item.detection_summary = expected_summary
    db.commit()


def _risk_score_from_summary(summary: dict[str, int]) -> int:
    weighted = 0.0
    for entity, count in summary.items():
        weighted += RISK_ENTITY_WEIGHTS.get(entity, 2.0) * max(0, int(count))
    if weighted <= 0:
        return 0
    return int(round(min(100.0, 100.0 * (1.0 - math.exp(-weighted / 20.0)))))


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _serialize_datetime(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _scan_with_virustotal_hash(file_sha256: str) -> dict:
    if not VIRUSTOTAL_ENABLED:
        return {
            "status": "unknown",
            "source": "virustotal_disabled",
            "payload": {"reason": "VIRUSTOTAL_ENABLED is false or API key missing"},
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT_SECONDS)
    except Exception as exc:
        return {
            "status": "unknown",
            "source": "virustotal_error",
            "payload": {"error": str(exc)},
        }

    if response.status_code == 404:
        return {
            "status": "unknown",
            "source": "virustotal_hash",
            "payload": {"found": False, "reason": "hash_not_found"},
        }

    if response.status_code != 200:
        return {
            "status": "unknown",
            "source": "virustotal_error",
            "payload": {"status_code": response.status_code, "body": response.text[:500]},
        }

    data = response.json()
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    status = "malicious" if (malicious > 0 or suspicious > 0) else ("clean" if harmless > 0 else "unknown")

    return {
        "status": status,
        "source": "virustotal_hash",
        "payload": {
            "found": True,
            "sha256": file_sha256,
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            },
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation"),
        },
    }


def _resolve_malware_scan_result(db: Session, file_sha256: str) -> dict:
    cached = (
        db.query(FileRecord)
        .filter(FileRecord.file_sha256 == file_sha256)
        .filter(FileRecord.malware_scan_status.isnot(None))
        .order_by(FileRecord.id.desc())
        .first()
    )
    if cached and cached.malware_scan_status in {"clean", "malicious", "unknown"}:
        payload = {}
        if cached.malware_scan_payload:
            try:
                payload = json.loads(cached.malware_scan_payload)
            except Exception:
                payload = {"raw": cached.malware_scan_payload}
        return {
            "status": cached.malware_scan_status,
            "source": "cache",
            "payload": payload,
        }
    return _scan_with_virustotal_hash(file_sha256)


def _is_eicar_test_file(raw_bytes: bytes) -> bool:
    return EICAR_TEST_SIGNATURE in raw_bytes


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    mode: str = Form("mask"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds upload limit ({MAX_UPLOAD_MB} MB)",
        )
    if not is_supported_file(file.filename, content_type=file.content_type, file_bytes=raw_bytes):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unsupported file. Supported types include SQL, CSV, JSON, PDF, DOCX, TXT, PNG/JPG, "
                "Excel, and other text-based structured/unstructured formats."
            ),
        )
    for signature in BLOCKED_BINARY_SIGNATURES:
        if raw_bytes.startswith(signature):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Executable binary uploads are blocked by security policy.",
            )

    if _is_eicar_test_file(raw_bytes):
        file_sha256 = sha256_hex(raw_bytes)
        write_audit_log(
            db,
            current_user.id,
            "MALWARE_BLOCK",
            f"Blocked upload filename='{file.filename}' sha256={file_sha256} source=local_eicar_signature",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload blocked: malware test signature detected (EICAR).",
        )

    file_sha256 = sha256_hex(raw_bytes)
    malware_scan = _resolve_malware_scan_result(db, file_sha256)
    should_block = malware_scan["status"] == "malicious" or (
        VIRUSTOTAL_BLOCK_UNKNOWN and malware_scan["status"] == "unknown"
    )
    if should_block:
        write_audit_log(
            db,
            current_user.id,
            "MALWARE_BLOCK",
            f"Blocked upload filename='{file.filename}' sha256={file_sha256} source={malware_scan.get('source')}",
        )
        block_reason = (
            "Upload blocked: file flagged as malicious by malware scan."
            if malware_scan["status"] == "malicious"
            else "Upload blocked: malware scan returned unknown and strict policy is enabled."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=block_reason,
        )

    ext = Path(file.filename).suffix.lower()
    effective_mode = "redact" if ext in {".pdf", ".png", ".jpg", ".jpeg"} else mode

    encryption_payload = encrypt_file_payload(raw_bytes)
    wire_bytes = pack_envelope_ciphertext(
        encryption_payload["cipher_bytes"],
        encryption_payload["data_nonce"],
        encryption_payload["wrap_nonce"],
    )

    file_key = f"{uuid.uuid4().hex}_{file.filename}"
    original_path = ORIGINAL_DIR / f"{file_key}.enc"
    _save_bytes(original_path, wire_bytes)

    expires_at = datetime.utcnow() + timedelta(days=ORIGINAL_RETENTION_DAYS)

    file_record = FileRecord(
        filename=file.filename,
        content_type=file.content_type,
        original_path=str(original_path),
        sanitized_path="",
        uploaded_by=current_user.id,
        sanitization_mode=effective_mode,
        pii_count=0,
        detection_summary="",
        encrypted_dek=encryption_payload["encrypted_dek"],
        encryption_version=encryption_payload["encryption_version"],
        file_sha256=encryption_payload["file_sha256"],
        cipher_sha256=encryption_payload["cipher_sha256"],
        malware_scan_status=malware_scan.get("status", "unknown"),
        malware_scan_source=malware_scan.get("source", "none"),
        malware_scan_payload=json.dumps(malware_scan.get("payload", {}), ensure_ascii=False),
        retention_expires_at=expires_at,
        legal_hold=False,
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    write_audit_log(
        db,
        current_user.id,
        "FILE_UPLOAD",
        (
            f"Uploaded original file '{file.filename}' file_id={file_record.id} "
            f"encryption={file_record.encryption_version} retention_expires_at={expires_at.isoformat()}"
        ),
    )

    return {
        "message": "File uploaded successfully. Sanitization is generated on-demand.",
        "file_id": file_record.id,
        "filename": file_record.filename,
        "sanitization_mode": effective_mode,
        "pii_count": file_record.pii_count,
        "entities": {},
        "malware_scan_status": file_record.malware_scan_status,
        "malware_scan_source": file_record.malware_scan_source,
        "sanitized_downloads": {
            "txt": True,
            "original_format": True,
        },
        "retention_expires_at": file_record.retention_expires_at,
    }


@router.get("")
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(FileRecord)
    if current_user.role != "admin":
        query = query.filter(FileRecord.uploaded_by == current_user.id)
    files = query.order_by(FileRecord.upload_time.desc()).all()
    write_audit_log(db, current_user.id, "USER_ACCESS", "Viewed files list")
    return [
        {
            "id": item.id,
            "filename": item.filename,
            "uploaded_by": item.uploaded_by,
            "upload_time": item.upload_time,
            "pii_count": item.pii_count,
            "sanitization_mode": _effective_mode(item),
            "detection_summary": json.loads(item.detection_summary) if item.detection_summary else {},
            "malware_scan_status": item.malware_scan_status or "unknown",
            "malware_scan_source": item.malware_scan_source or "none",
            "sanitized_original_download_available": True,
            "retention_expires_at": item.retention_expires_at,
            "legal_hold": item.legal_hold,
        }
        for item in files
    ]


@router.get("/sanitized-catalog")
def list_all_sanitized_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    files = db.query(FileRecord).order_by(FileRecord.upload_time.desc()).all()
    write_audit_log(db, current_user.id, "USER_ACCESS", "Viewed shared sanitized catalog")
    return [
        {
            "id": item.id,
            "filename": item.filename,
            "uploaded_by": item.uploaded_by,
            "upload_time": item.upload_time,
            "pii_count": item.pii_count,
            "sanitization_mode": _effective_mode(item),
            "detection_summary": json.loads(item.detection_summary) if item.detection_summary else {},
            "malware_scan_status": item.malware_scan_status or "unknown",
            "malware_scan_source": item.malware_scan_source or "none",
            "retention_expires_at": item.retention_expires_at,
        }
        for item in files
    ]


@router.get("/search")
def search_sanitized_records(
    q: str = Query(..., min_length=2),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    matches = []
    query = db.query(FileRecord)
    if current_user.role != "admin":
        query = query.filter(FileRecord.uploaded_by == current_user.id)
    candidates = query.order_by(FileRecord.upload_time.desc()).all()
    term = q.lower()

    for item in candidates:
        payload = _build_sanitized_payload(item)
        _update_detection_metadata(db, item, payload)
        sanitized_text = payload["sanitized_text"]
        if term in sanitized_text.lower() or term in item.filename.lower():
            matches.append(
                {
                    "id": item.id,
                    "filename": item.filename,
                    "upload_time": item.upload_time,
                    "preview": sanitized_text[:350],
                }
            )

    write_audit_log(db, current_user.id, "USER_ACCESS", f"Searched sanitized records q='{q}'")
    return {"query": q, "count": len(matches), "results": matches}


@router.get("/risk-dashboard")
def get_risk_dashboard(
    months: int = Query(12, ge=1, le=36),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(FileRecord)
    if current_user.role != "admin":
        query = query.filter(FileRecord.uploaded_by == current_user.id)
    files = query.order_by(FileRecord.upload_time.desc()).all()

    per_file_rows: list[dict] = []
    entity_totals: dict[str, int] = defaultdict(int)
    monthly_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    monthly_scores: dict[str, list[int]] = defaultdict(list)
    user_totals: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    now = datetime.utcnow()
    cutoff_month = (
        now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        - timedelta(days=31 * (months - 1))
    )

    for item in files:
        summary: dict[str, int] = {}
        if item.detection_summary:
            try:
                summary = json.loads(item.detection_summary)
            except Exception:
                summary = {}

        if not summary and (item.pii_count or 0) == 0:
            payload = _build_sanitized_payload(item)
            _update_detection_metadata(db, item, payload)
            summary = payload.get("summary", {}) or {}

        pii_count = int(sum(max(0, int(v)) for v in summary.values()))
        score = _risk_score_from_summary(summary)
        per_file_rows.append(
            {
                "file_id": item.id,
                "filename": item.filename,
                "uploaded_by": item.uploaded_by,
                "upload_time": item.upload_time,
                "pii_count": pii_count,
                "risk_score": score,
                "risk_level": _risk_level(score),
                "entities": summary,
            }
        )

        for entity, count in summary.items():
            entity_totals[entity] += int(count)
            user_totals[item.uploaded_by][entity] += int(count)

        if item.upload_time and item.upload_time >= cutoff_month:
            month_key = item.upload_time.strftime("%Y-%m")
            for entity, count in summary.items():
                monthly_totals[month_key][entity] += int(count)
            monthly_scores[month_key].append(score)

    per_file_rows.sort(key=lambda r: (r["risk_score"], r["pii_count"], r["upload_time"]), reverse=True)
    top_entities = sorted(entity_totals.items(), key=lambda kv: kv[1], reverse=True)

    month_keys: list[str] = []
    cursor = cutoff_month
    for _ in range(months):
        month_keys.append(cursor.strftime("%Y-%m"))
        cursor = (cursor + timedelta(days=32)).replace(day=1)

    monthly_trend = []
    for month_key in month_keys:
        month_entity_counts = monthly_totals.get(month_key, {})
        month_pii = int(sum(month_entity_counts.values()))
        scores = monthly_scores.get(month_key, [])
        avg_score = int(round(sum(scores) / len(scores))) if scores else 0
        monthly_trend.append(
            {
                "month": month_key,
                "pii_count": month_pii,
                "avg_risk_score": avg_score,
            }
        )

    heatmap_entities = [entity for entity, _ in top_entities[:8]]
    exposure_heatmap = [
        {
            "entity": entity,
            "values": [int(monthly_totals.get(month_key, {}).get(entity, 0)) for month_key in month_keys],
        }
        for entity in heatmap_entities
    ]

    per_user_scores = []
    if current_user.role == "admin":
        user_rows = db.query(User.id, User.username).all()
        user_name_map = {uid: uname for uid, uname in user_rows}
        for user_id, summary in user_totals.items():
            score = _risk_score_from_summary(summary)
            total_pii = int(sum(summary.values()))
            per_user_scores.append(
                {
                    "user_id": user_id,
                    "username": user_name_map.get(user_id, f"user-{user_id}"),
                    "pii_count": total_pii,
                    "risk_score": score,
                    "risk_level": _risk_level(score),
                    "entities": dict(summary),
                }
            )
        per_user_scores.sort(key=lambda r: (r["risk_score"], r["pii_count"]), reverse=True)

    overall_summary = dict(entity_totals)
    overall_score = _risk_score_from_summary(overall_summary)
    total_pii = int(sum(overall_summary.values()))
    scope = "global" if current_user.role == "admin" else "personal"

    write_audit_log(
        db,
        current_user.id,
        "USER_ACCESS",
        f"Viewed risk dashboard scope={scope} files={len(per_file_rows)} months={months}",
    )

    return {
        "scope": scope,
        "months": months,
        "overall": {
            "file_count": len(per_file_rows),
            "pii_count": total_pii,
            "risk_score": overall_score,
            "risk_level": _risk_level(overall_score),
        },
        "top_entities": [{"entity": entity, "count": count} for entity, count in top_entities[:10]],
        "monthly_trend": monthly_trend,
        "exposure_heatmap": {
            "months": month_keys,
            "rows": exposure_heatmap,
        },
        "per_file_scores": per_file_rows[:200],
        "per_user_scores": per_user_scores,
    }


@router.get("/admin/backup-download")
def download_backup_zip(
    x_stepup_password: str | None = Header(default=None, alias="X-Stepup-Password"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    if BACKUP_STEPUP_REQUIRED:
        if not x_stepup_password:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up password required")
        if not verify_password(x_stepup_password, admin_user.password_hash):
            write_audit_log(db, admin_user.id, "STEPUP_FAIL", "Failed step-up for backup download")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid step-up password")

    users = db.query(User).order_by(User.id.asc()).all()
    files = db.query(FileRecord).order_by(FileRecord.id.asc()).all()
    audits = db.query(AuditLog).order_by(AuditLog.id.asc()).all()

    db_dump = {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "password_hash": user.password_hash,
                "role": user.role,
                "created_at": _serialize_datetime(user.created_at),
                "failed_login_attempts": user.failed_login_attempts,
                "locked_until": _serialize_datetime(user.locked_until),
            }
            for user in users
        ],
        "files": [
            {
                "id": item.id,
                "filename": item.filename,
                "content_type": item.content_type,
                "original_path": item.original_path,
                "sanitized_path": item.sanitized_path,
                "uploaded_by": item.uploaded_by,
                "upload_time": _serialize_datetime(item.upload_time),
                "sanitization_mode": item.sanitization_mode,
                "pii_count": item.pii_count,
                "detection_summary": item.detection_summary,
                "encrypted_dek": item.encrypted_dek,
                "encryption_version": item.encryption_version,
                "file_sha256": item.file_sha256,
                "cipher_sha256": item.cipher_sha256,
                "malware_scan_status": item.malware_scan_status,
                "malware_scan_source": item.malware_scan_source,
                "malware_scan_payload": item.malware_scan_payload,
                "retention_expires_at": _serialize_datetime(item.retention_expires_at),
                "legal_hold": item.legal_hold,
            }
            for item in files
        ],
        "audit_logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "details": log.details,
                "timestamp": _serialize_datetime(log.timestamp),
                "prev_hash": log.prev_hash,
                "log_hash": log.log_hash,
            }
            for log in audits
        ],
    }

    config_snapshot = {
        "APP_ENV": os.getenv("APP_ENV", "development"),
        "HOST": os.getenv("HOST", "0.0.0.0"),
        "PORT": os.getenv("PORT", "8000"),
        "MAX_UPLOAD_MB": os.getenv("MAX_UPLOAD_MB", "25"),
        "ORIGINAL_RETENTION_DAYS": os.getenv("ORIGINAL_RETENTION_DAYS", "30"),
        "STEPUP_REQUIRED_FOR_RAW_DOWNLOAD": os.getenv("STEPUP_REQUIRED_FOR_RAW_DOWNLOAD", "true"),
        "BACKUP_STEPUP_REQUIRED": os.getenv("BACKUP_STEPUP_REQUIRED", "true"),
        "USE_PRESIDIO": os.getenv("USE_PRESIDIO", "true"),
        "USE_LLM": os.getenv("USE_LLM", "false"),
        "USE_LLM_OPEN_SOURCE": os.getenv("USE_LLM_OPEN_SOURCE", "false"),
        "REQUIRE_AADHAAR_VERHOEFF": os.getenv("REQUIRE_AADHAAR_VERHOEFF", "false"),
        "OCR_LANG": os.getenv("OCR_LANG", "en"),
        "OCR_USE_ANGLE_CLS": os.getenv("OCR_USE_ANGLE_CLS", "true"),
        "USE_QR_SCAN": os.getenv("USE_QR_SCAN", "true"),
    }

    db_dump_bytes = json.dumps(db_dump, ensure_ascii=False, indent=2).encode("utf-8")
    audit_jsonl = "\n".join(
        json.dumps(
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "details": log.details,
                "timestamp": _serialize_datetime(log.timestamp),
                "prev_hash": log.prev_hash,
                "log_hash": log.log_hash,
            },
            ensure_ascii=False,
        )
        for log in audits
    ).encode("utf-8")

    backup_buffer = io.BytesIO()
    original_file_count = 0
    original_total_bytes = 0
    missing_originals: list[str] = []

    with zipfile.ZipFile(backup_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("database_dump.json", db_dump_bytes)
        zf.writestr("audit_logs.jsonl", audit_jsonl)
        zf.writestr("config_snapshot.json", json.dumps(config_snapshot, ensure_ascii=False, indent=2).encode("utf-8"))

        for item in files:
            original_path = Path(item.original_path)
            if not original_path.exists() or not original_path.is_file():
                missing_originals.append(str(original_path))
                continue
            try:
                payload = _read_bytes(str(original_path))
                original_file_count += 1
                original_total_bytes += len(payload)
                zf.writestr(f"originals/{original_path.name}", payload)
            except Exception:
                missing_originals.append(str(original_path))

        manifest = {
            "version": 1,
            "created_at_utc": datetime.utcnow().isoformat(),
            "created_by_user_id": admin_user.id,
            "counts": {
                "users": len(users),
                "files": len(files),
                "audit_logs": len(audits),
                "original_files_included": original_file_count,
                "missing_original_files": len(missing_originals),
            },
            "sizes": {
                "database_dump_bytes": len(db_dump_bytes),
                "audit_jsonl_bytes": len(audit_jsonl),
                "original_total_bytes": original_total_bytes,
            },
            "checksums": {
                "database_dump_sha256": sha256_hex(db_dump_bytes),
                "audit_jsonl_sha256": sha256_hex(audit_jsonl),
            },
            "missing_original_paths": missing_originals,
            "notes": "Encrypted originals are included as-is. Restore requires FILE_MASTER_KEY and DB metadata.",
        }
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))

    backup_bytes = backup_buffer.getvalue()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"pii_guardian_backup_{timestamp}.zip"

    write_audit_log(
        db,
        admin_user.id,
        "BACKUP_EXPORT",
        (
            f"Downloaded backup zip users={len(users)} files={len(files)} audits={len(audits)} "
            f"originals_included={original_file_count} missing_originals={len(missing_originals)}"
        ),
    )

    return StreamingResponse(
        iter([backup_bytes]),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{file_id}/raw-preview")
def raw_preview(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    _ensure_user_can_access_file(current_user, item)

    raw_bytes = _read_original_verified(item)
    extracted_text, parser = extract_text_from_file(item.filename, raw_bytes)

    write_audit_log(db, current_user.id, "USER_ACCESS", f"Viewed raw preview for file_id={file_id}")
    return {"file_id": item.id, "filename": item.filename, "parser": parser, "raw_preview": extracted_text[:5000]}


@router.get("/{file_id}/sanitized-preview")
def sanitized_preview(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    payload = _build_sanitized_payload(item)
    _update_detection_metadata(db, item, payload)

    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    write_audit_log(
        db,
        current_user.id,
        "PII_DETECTION",
        f"file_id={file_id} pii_count={len(findings)} entities={json.dumps(summary)}",
    )
    write_audit_log(db, current_user.id, "USER_ACCESS", f"Viewed sanitized preview for file_id={file_id}")

    return {
        "file_id": item.id,
        "filename": item.filename,
        "sanitized_preview": payload["sanitized_text"][:5000],
        "pii_count": len(findings),
        "entities": summary,
    }


@router.get("/{file_id}/download")
def download_sanitized_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    payload = _build_sanitized_payload(item)
    _update_detection_metadata(db, item, payload)

    data = payload["sanitized_text"].encode("utf-8")
    filename = f"{Path(item.filename).stem}.sanitized.txt"

    write_audit_log(db, current_user.id, "DOWNLOAD", f"Downloaded sanitized file (on-demand) file_id={file_id}")

    return StreamingResponse(
        iter([data]),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{file_id}/download-sanitized-original")
def download_sanitized_original_format_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    payload = _build_sanitized_payload(item)
    _update_detection_metadata(db, item, payload)

    ext = Path(item.filename).suffix.lower()
    filename = f"{Path(item.filename).stem}.sanitized{ext}"
    media_type = mimetypes.guess_type(filename)[0] or payload.get("sanitized_original_media_type") or "application/octet-stream"

    write_audit_log(
        db,
        current_user.id,
        "DOWNLOAD",
        f"Downloaded sanitized original-format file (on-demand) file_id={file_id} ext={ext}",
    )

    return StreamingResponse(
        iter([payload["sanitized_original_bytes"]]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{file_id}/download-original")
def download_original_file(
    file_id: int,
    x_stepup_password: str | None = Header(default=None, alias="X-Stepup-Password"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    _ensure_user_can_access_file(current_user, item)

    if STEPUP_REQUIRED_FOR_RAW_DOWNLOAD:
        if not x_stepup_password:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up password required")
        if not verify_password(x_stepup_password, current_user.password_hash):
            write_audit_log(db, current_user.id, "STEPUP_FAIL", f"Failed step-up for file_id={file_id}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid step-up password")

    payload = _read_original_verified(item)
    media_type = item.content_type or mimetypes.guess_type(item.filename)[0] or "application/octet-stream"

    write_audit_log(
        db,
        current_user.id,
        "DOWNLOAD",
        f"Downloaded original file file_id={file_id} stepup={STEPUP_REQUIRED_FOR_RAW_DOWNLOAD}",
    )

    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{item.filename}"'},
    )


@router.post("/admin/cleanup-expired")
def cleanup_expired_originals(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    targets = (
        db.query(FileRecord)
        .filter(FileRecord.legal_hold == False)  # noqa: E712
        .filter(FileRecord.retention_expires_at.isnot(None))
        .filter(FileRecord.retention_expires_at < now)
        .all()
    )

    deleted_count = 0
    for item in targets:
        try:
            path = Path(item.original_path)
            if path.exists() and path.is_file():
                path.unlink()
        except Exception:
            pass
        db.delete(item)
        deleted_count += 1

    db.commit()
    write_audit_log(db, admin_user.id, "RETENTION_CLEANUP", f"Deleted expired originals count={deleted_count}")
    return {"deleted_count": deleted_count, "timestamp": now}


@router.post("/{file_id}/legal-hold")
def set_legal_hold(
    file_id: int,
    hold: bool = Query(...),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)
    item.legal_hold = hold
    db.commit()

    write_audit_log(db, admin_user.id, "LEGAL_HOLD", f"Set legal_hold={hold} for file_id={file_id}")
    return {"file_id": file_id, "legal_hold": hold}


@router.delete("/{file_id}")
def delete_file_record(
    file_id: int,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    item = _get_file_or_404(db, file_id)

    paths_to_delete: list[Path] = []
    if item.original_path:
        paths_to_delete.append(Path(item.original_path))
    if item.sanitized_path:
        paths_to_delete.append(Path(item.sanitized_path))

    for path in paths_to_delete:
        try:
            if path.exists() and path.is_file():
                path.unlink()
        except Exception:
            pass

    deleted_filename = item.filename
    db.delete(item)
    db.commit()

    write_audit_log(db, admin_user.id, "FILE_DELETE", f"Deleted file_id={file_id} filename='{deleted_filename}'")
    return {"message": "File deleted successfully", "file_id": file_id}

