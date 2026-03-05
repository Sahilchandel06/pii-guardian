import json
import mimetypes
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.file import FileRecord
from app.models.user import User
from app.services.audit_service import write_audit_log
from app.services.file_parser import extract_text_from_file, is_supported_file
from app.services.pii_detector import detect_pii, summarize_findings
from app.services.sanitizer import sanitize_text
from app.utils.security import get_current_admin, get_current_user
from app.utils.storage_crypto import decrypt_bytes, encrypt_bytes

router = APIRouter(prefix="/files", tags=["Files"])

BASE_UPLOAD_DIR = Path("secure_storage")
ORIGINAL_DIR = BASE_UPLOAD_DIR / "originals"
SANITIZED_DIR = BASE_UPLOAD_DIR / "sanitized"
ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)
SANITIZED_DIR.mkdir(parents=True, exist_ok=True)


def _read_decrypted(path: str) -> bytes:
    with open(path, "rb") as infile:
        return decrypt_bytes(infile.read())


def _save_encrypted(path: Path, data: bytes) -> None:
    with open(path, "wb") as outfile:
        outfile.write(encrypt_bytes(data))


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    mode: str = Form("mask"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    if not is_supported_file(file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported format. Allowed: SQL, CSV, JSON, PDF, DOCX, TXT, PNG, JPG",
        )

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    file_key = f"{uuid.uuid4().hex}_{file.filename}"
    original_path = ORIGINAL_DIR / f"{file_key}.enc"

    _save_encrypted(original_path, raw_bytes)
    write_audit_log(db, admin_user.id, "FILE_UPLOAD", f"Uploaded file '{file.filename}'")

    try:
        extracted_text, parser = extract_text_from_file(file.filename, raw_bytes)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Failed to parse file: {exc}") from exc

    findings = detect_pii(extracted_text)
    summary = summarize_findings(findings)
    write_audit_log(
        db,
        admin_user.id,
        "PII_DETECTION",
        f"file='{file.filename}' pii_count={len(findings)} entities={json.dumps(summary)}",
    )

    sanitized_text, token_map = sanitize_text(extracted_text, findings, mode=mode)
    sanitized_filename = f"{uuid.uuid4().hex}_{Path(file.filename).stem}.sanitized.txt"
    sanitized_path = SANITIZED_DIR / f"{sanitized_filename}.enc"
    _save_encrypted(sanitized_path, sanitized_text.encode("utf-8"))

    file_record = FileRecord(
        filename=file.filename,
        content_type=file.content_type,
        original_path=str(original_path),
        sanitized_path=str(sanitized_path),
        uploaded_by=admin_user.id,
        sanitization_mode=mode,
        pii_count=len(findings),
        detection_summary=json.dumps(summary),
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    write_audit_log(
        db,
        admin_user.id,
        "FILE_SANITIZED",
        f"file_id={file_record.id} parser={parser} mode={mode}",
    )

    return {
        "message": "File uploaded and sanitized successfully",
        "file_id": file_record.id,
        "filename": file_record.filename,
        "sanitization_mode": mode,
        "pii_count": file_record.pii_count,
        "entities": summary,
        "token_count": len(token_map),
    }


@router.get("")
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    files = db.query(FileRecord).order_by(FileRecord.upload_time.desc()).all()
    write_audit_log(db, current_user.id, "USER_ACCESS", "Viewed files list")
    return [
        {
            "id": item.id,
            "filename": item.filename,
            "uploaded_by": item.uploaded_by,
            "upload_time": item.upload_time,
            "pii_count": item.pii_count,
            "sanitization_mode": item.sanitization_mode,
            "detection_summary": json.loads(item.detection_summary) if item.detection_summary else {},
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
    candidates = db.query(FileRecord).order_by(FileRecord.upload_time.desc()).all()
    term = q.lower()

    for item in candidates:
        sanitized_text = _read_decrypted(item.sanitized_path).decode("utf-8", errors="ignore")
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


@router.get("/{file_id}/raw-preview")
def raw_preview(
    file_id: int,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    item = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    raw_bytes = _read_decrypted(item.original_path)
    extracted_text, parser = extract_text_from_file(item.filename, raw_bytes)

    write_audit_log(db, admin_user.id, "USER_ACCESS", f"Viewed raw preview for file_id={file_id}")
    return {"file_id": item.id, "filename": item.filename, "parser": parser, "raw_preview": extracted_text[:5000]}


@router.get("/{file_id}/sanitized-preview")
def sanitized_preview(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    sanitized_text = _read_decrypted(item.sanitized_path).decode("utf-8", errors="ignore")

    write_audit_log(db, current_user.id, "USER_ACCESS", f"Viewed sanitized preview for file_id={file_id}")
    return {"file_id": item.id, "filename": item.filename, "sanitized_preview": sanitized_text[:5000]}


@router.get("/{file_id}/download")
def download_sanitized_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    payload = _read_decrypted(item.sanitized_path)
    filename = f"{Path(item.filename).stem}.sanitized.txt"

    write_audit_log(db, current_user.id, "DOWNLOAD", f"Downloaded sanitized file file_id={file_id}")

    return StreamingResponse(
        iter([payload]),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{file_id}/download-original")
def download_original_file(
    file_id: int,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    item = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    payload = _read_decrypted(item.original_path)
    media_type = item.content_type or mimetypes.guess_type(item.filename)[0] or "application/octet-stream"

    write_audit_log(db, admin_user.id, "DOWNLOAD", f"Downloaded original file file_id={file_id}")

    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{item.filename}"'},
    )
