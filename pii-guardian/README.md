# PII Guardian

PII Guardian is a FastAPI + React platform for detecting and sanitizing PII across structured and unstructured files with RBAC, encrypted storage, and audit logging.

## Implemented Coverage

- Roles:
  - Admin: upload, view raw, view sanitized, manage users, view audit logs, download raw/sanitized.
  - User: view sanitized only, search/filter, download sanitized only.
- PII detection:
  - Regex + Presidio NER.
  - Entities: name, PAN, Aadhaar, email, phone, IP, address, DOB, VID, UPI handles.
- Sanitization:
  - `mask`, `redact`, `tokenize`.
- File formats:
  - Mandatory: SQL, PDF, DOCX.
  - Also: TXT, CSV, JSON, PNG/JPG, XLS/XLSX family.
  - Generic text-based fallback for other text-like files.
- Security:
  - Encryption at rest for original/sanitized files.
  - JWT auth.
  - Configurable CORS.
  - Request rate limiting and upload file-size limits.
  - Optional HTTPS using SSL cert/key env vars.
- Audit:
  - Upload, detection, file access, searches, downloads, auth/user management events.

## Quick Start

## 1) Backend

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python main.py
```

API default: `http://127.0.0.1:8000`

To run HTTPS locally, set in `.env`:

```env
SSL_CERTFILE=path/to/cert.pem
SSL_KEYFILE=path/to/key.pem
```

Then start backend with `python main.py`.

## 2) Frontend

```powershell
cd frontend\frontend
npm install
npm run dev
```

App default: `http://localhost:5173`

Set explicit API base if needed:

```env
VITE_API_BASE_URL=https://127.0.0.1:8000
```

## Demo Dataset

Use files in `demo_samples/`:

- `sample_pii.sql`
- `sample_pii.pdf`
- `sample_pii.docx`

## Evaluation Demo Flow

1. Login as admin.
2. Upload SQL/PDF/DOCX from `demo_samples`.
3. Show detection count + entity summary after upload.
4. Open raw preview (admin) and sanitized preview (both roles).
5. Download sanitized TXT and sanitized original-format file.
6. Login as standard user and confirm raw preview/download are blocked.
7. Show search on sanitized records.
8. Open audit logs and show upload/access/download/detection events.

## Security Notes

- For production set:
  - `APP_ENV=production`
  - strong `JWT_SECRET_KEY`
  - `FILE_ENCRYPTION_KEY`
  - strict `CORS_ALLOW_ORIGINS`
  - HTTPS cert/key or reverse proxy TLS

## Known Constraints

- Binary proprietary formats that are not text/OCR/office supported are rejected.
- OCR quality depends on image clarity and installed Tesseract language packs.
