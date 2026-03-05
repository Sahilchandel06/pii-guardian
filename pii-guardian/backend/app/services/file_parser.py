import csv
import io
import json
import os

SUPPORTED_EXTENSIONS = {
    ".sql",
    ".csv",
    ".json",
    ".pdf",
    ".docx",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
}


def is_supported_file(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in SUPPORTED_EXTENSIONS


def extract_text_from_file(filename: str, file_bytes: bytes) -> tuple[str, str]:
    ext = os.path.splitext(filename.lower())[1]

    if ext in {".txt", ".sql"}:
        return file_bytes.decode("utf-8", errors="ignore"), ext[1:]

    if ext == ".json":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        parsed = json.loads(decoded)
        return json.dumps(parsed, indent=2, ensure_ascii=True), "json"

    if ext == ".csv":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(decoded))
        lines = [" | ".join(row) for row in reader]
        return "\n".join(lines), "csv"

    if ext == ".pdf":
        import pdfplumber

        chunks: list[str] = []
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                chunks.append(page.extract_text() or "")
        return "\n".join(chunks), "pdf"

    if ext == ".docx":
        from docx import Document

        doc = Document(io.BytesIO(file_bytes))
        return "\n".join(paragraph.text for paragraph in doc.paragraphs), "docx"

    if ext in {".png", ".jpg", ".jpeg"}:
        from PIL import Image
        import pytesseract

        image = Image.open(io.BytesIO(file_bytes))
        return pytesseract.image_to_string(image), "ocr_image"

    raise ValueError(f"Unsupported file type: {ext}")
