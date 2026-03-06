import csv
import io
import json
import mimetypes
import os
from collections import defaultdict
from typing import Any

from app.services.pii_detector import detect_pii
from app.services.sanitizer import sanitize_text

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
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".xls",
}

EXCEL_OPENXML_EXTENSIONS = {".xlsx", ".xlsm", ".xltx", ".xltm"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}


def is_supported_file(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in SUPPORTED_EXTENSIONS


def _collect_counts(chunks: list[list[dict[str, Any]]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for findings in chunks:
        for finding in findings:
            counts[finding["entity_type"]] += 1
    return dict(counts)


def _sanitize_chunk(text: str, mode: str) -> tuple[str, list[dict[str, Any]]]:
    findings = detect_pii(text)
    sanitized, _ = sanitize_text(text, findings, mode=mode)
    return sanitized, findings


def _sanitize_image(image, mode: str):
    import pytesseract
    from PIL import ImageDraw

    ocr = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    words: list[dict[str, Any]] = []
    cursor = 0
    pieces: list[str] = []

    for idx, raw_text in enumerate(ocr.get("text", [])):
        word = (raw_text or "").strip()
        if not word:
            continue
        conf = ocr.get("conf", ["0"])[idx]
        try:
            conf_value = float(conf)
        except ValueError:
            conf_value = -1.0
        if conf_value < 0:
            continue

        if pieces:
            pieces.append(" ")
            cursor += 1
        start = cursor
        pieces.append(word)
        cursor += len(word)

        words.append(
            {
                "start": start,
                "end": cursor,
                "left": int(ocr["left"][idx]),
                "top": int(ocr["top"][idx]),
                "width": int(ocr["width"][idx]),
                "height": int(ocr["height"][idx]),
            }
        )

    plain_text = "".join(pieces)
    sanitized_text, findings = _sanitize_chunk(plain_text, mode)

    redacted = image.copy().convert("RGB")
    draw = ImageDraw.Draw(redacted)
    for word in words:
        overlaps = any(
            finding["start"] < word["end"] and word["start"] < finding["end"]
            for finding in findings
        )
        if overlaps:
            x0 = word["left"]
            y0 = word["top"]
            x1 = x0 + max(1, word["width"])
            y1 = y0 + max(1, word["height"])
            draw.rectangle([x0, y0, x1, y1], fill="black")

    return redacted, plain_text, sanitized_text, findings


def _extract_from_excel_openxml(file_bytes: bytes) -> tuple[str, str]:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(file_bytes), data_only=False)
    chunks: list[str] = []
    for sheet in wb.worksheets:
        chunks.append(f"[Sheet: {sheet.title}]")
        for row in sheet.iter_rows(values_only=True):
            values = ["" if value is None else str(value) for value in row]
            if any(values):
                chunks.append(" | ".join(values))
    return "\n".join(chunks), "excel"


def _extract_from_xls(file_bytes: bytes) -> tuple[str, str]:
    import xlrd

    wb = xlrd.open_workbook(file_contents=file_bytes)
    chunks: list[str] = []
    for sheet in wb.sheets():
        chunks.append(f"[Sheet: {sheet.name}]")
        for row_idx in range(sheet.nrows):
            row_values = [str(sheet.cell_value(row_idx, col_idx) or "") for col_idx in range(sheet.ncols)]
            if any(row_values):
                chunks.append(" | ".join(row_values))
    return "\n".join(chunks), "excel_xls"


def extract_text_from_file(filename: str, file_bytes: bytes) -> tuple[str, str]:
    ext = os.path.splitext(filename.lower())[1]

    if ext in {".txt", ".sql"}:
        return file_bytes.decode("utf-8", errors="ignore"), ext[1:]

    if ext == ".json":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        parsed = json.loads(decoded)
        return json.dumps(parsed, indent=2, ensure_ascii=False), "json"

    if ext == ".csv":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(decoded))
        lines = [",".join(row) for row in reader]
        return "\n".join(lines), "csv"

    if ext == ".pdf":
        import fitz
        import pytesseract
        from PIL import Image

        doc = fitz.open(stream=file_bytes, filetype="pdf")
        chunks: list[str] = []
        for page in doc:
            text = (page.get_text("text") or "").strip()
            if text:
                chunks.append(text)
                continue

            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            chunks.append(pytesseract.image_to_string(image))
        return "\n\n".join(chunks), "pdf_ocr"

    if ext == ".docx":
        from docx import Document

        doc = Document(io.BytesIO(file_bytes))
        lines: list[str] = [paragraph.text for paragraph in doc.paragraphs if paragraph.text]
        for table in doc.tables:
            for row in table.rows:
                lines.append(" | ".join(cell.text for cell in row.cells))
        return "\n".join(lines), "docx"

    if ext in IMAGE_EXTENSIONS:
        from PIL import Image

        image = Image.open(io.BytesIO(file_bytes))
        _, plain_text, _, _ = _sanitize_image(image, mode="mask")
        return plain_text, "ocr_image"

    if ext in EXCEL_OPENXML_EXTENSIONS:
        return _extract_from_excel_openxml(file_bytes)

    if ext == ".xls":
        return _extract_from_xls(file_bytes)

    raise ValueError(f"Unsupported file type: {ext}")


def _sanitize_json(obj: Any, mode: str, findings_bucket: list[list[dict[str, Any]]]) -> Any:
    if isinstance(obj, str):
        sanitized, findings = _sanitize_chunk(obj, mode)
        findings_bucket.append(findings)
        return sanitized
    if isinstance(obj, list):
        return [_sanitize_json(item, mode, findings_bucket) for item in obj]
    if isinstance(obj, dict):
        return {key: _sanitize_json(value, mode, findings_bucket) for key, value in obj.items()}
    return obj


def sanitize_file_preserving_format(
    filename: str,
    file_bytes: bytes,
    mode: str,
) -> dict[str, Any]:
    ext = os.path.splitext(filename.lower())[1]
    media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    if ext in {".txt", ".sql"}:
        raw_text = file_bytes.decode("utf-8", errors="ignore")
        sanitized_text, findings = _sanitize_chunk(raw_text, mode)
        return {
            "sanitized_text": sanitized_text,
            "sanitized_original_bytes": sanitized_text.encode("utf-8"),
            "sanitized_original_ext": ext,
            "sanitized_original_media_type": "text/plain",
            "findings": findings,
            "summary": _collect_counts([findings]),
            "parser": ext[1:],
        }

    if ext == ".json":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        payload = json.loads(decoded)
        findings_bucket: list[list[dict[str, Any]]] = []
        sanitized_payload = _sanitize_json(payload, mode, findings_bucket)
        sanitized_json = json.dumps(sanitized_payload, indent=2, ensure_ascii=False)
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": sanitized_json,
            "sanitized_original_bytes": sanitized_json.encode("utf-8"),
            "sanitized_original_ext": ".json",
            "sanitized_original_media_type": "application/json",
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "json",
        }

    if ext == ".csv":
        decoded = file_bytes.decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(decoded))
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        findings_bucket: list[list[dict[str, Any]]] = []

        for row in reader:
            clean_row: list[str] = []
            for cell in row:
                sanitized_cell, findings = _sanitize_chunk(cell, mode)
                findings_bucket.append(findings)
                clean_row.append(sanitized_cell)
            writer.writerow(clean_row)

        sanitized_csv = output.getvalue()
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": sanitized_csv,
            "sanitized_original_bytes": sanitized_csv.encode("utf-8"),
            "sanitized_original_ext": ".csv",
            "sanitized_original_media_type": "text/csv",
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "csv",
        }

    if ext in EXCEL_OPENXML_EXTENSIONS:
        from openpyxl import load_workbook

        wb = load_workbook(io.BytesIO(file_bytes), data_only=False)
        findings_bucket: list[list[dict[str, Any]]] = []
        preview_lines: list[str] = []

        for sheet in wb.worksheets:
            preview_lines.append(f"[Sheet: {sheet.title}]")
            for row in sheet.iter_rows():
                row_preview: list[str] = []
                for cell in row:
                    value = cell.value
                    if isinstance(value, str):
                        sanitized_cell, findings = _sanitize_chunk(value, mode)
                        findings_bucket.append(findings)
                        cell.value = sanitized_cell
                        row_preview.append(sanitized_cell)
                    else:
                        row_preview.append("" if value is None else str(value))
                if any(row_preview):
                    preview_lines.append(" | ".join(row_preview))

        output = io.BytesIO()
        wb.save(output)
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": "\n".join(preview_lines),
            "sanitized_original_bytes": output.getvalue(),
            "sanitized_original_ext": ext,
            "sanitized_original_media_type": media_type,
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "excel",
        }

    if ext == ".xls":
        import xlrd
        import xlwt

        workbook = xlrd.open_workbook(file_contents=file_bytes)
        out_workbook = xlwt.Workbook()
        findings_bucket: list[list[dict[str, Any]]] = []
        preview_lines: list[str] = []

        for sheet_idx in range(workbook.nsheets):
            in_sheet = workbook.sheet_by_index(sheet_idx)
            out_sheet = out_workbook.add_sheet(in_sheet.name[:31] or f"Sheet{sheet_idx + 1}")
            preview_lines.append(f"[Sheet: {in_sheet.name}]")

            for row_idx in range(in_sheet.nrows):
                row_preview: list[str] = []
                for col_idx in range(in_sheet.ncols):
                    value = in_sheet.cell_value(row_idx, col_idx)
                    if isinstance(value, str):
                        sanitized_cell, findings = _sanitize_chunk(value, mode)
                        findings_bucket.append(findings)
                        out_sheet.write(row_idx, col_idx, sanitized_cell)
                        row_preview.append(sanitized_cell)
                    else:
                        out_sheet.write(row_idx, col_idx, value)
                        row_preview.append("" if value is None else str(value))
                if any(row_preview):
                    preview_lines.append(" | ".join(row_preview))

        output = io.BytesIO()
        out_workbook.save(output)
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": "\n".join(preview_lines),
            "sanitized_original_bytes": output.getvalue(),
            "sanitized_original_ext": ".xls",
            "sanitized_original_media_type": "application/vnd.ms-excel",
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "excel_xls",
        }

    if ext == ".docx":
        from docx import Document

        doc = Document(io.BytesIO(file_bytes))
        findings_bucket: list[list[dict[str, Any]]] = []

        for paragraph in doc.paragraphs:
            if paragraph.text:
                sanitized_paragraph, findings = _sanitize_chunk(paragraph.text, mode)
                paragraph.text = sanitized_paragraph
                findings_bucket.append(findings)

        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text:
                        sanitized_cell, findings = _sanitize_chunk(cell.text, mode)
                        cell.text = sanitized_cell
                        findings_bucket.append(findings)

        output = io.BytesIO()
        doc.save(output)
        preview_text, _ = extract_text_from_file(filename, output.getvalue())
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": preview_text,
            "sanitized_original_bytes": output.getvalue(),
            "sanitized_original_ext": ".docx",
            "sanitized_original_media_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "docx",
        }

    if ext in IMAGE_EXTENSIONS:
        from PIL import Image

        image = Image.open(io.BytesIO(file_bytes))
        redacted, _, sanitized_text, findings = _sanitize_image(image, mode)

        output = io.BytesIO()
        image_format = "PNG" if ext == ".png" else "JPEG"
        redacted.save(output, format=image_format)
        return {
            "sanitized_text": sanitized_text,
            "sanitized_original_bytes": output.getvalue(),
            "sanitized_original_ext": ext,
            "sanitized_original_media_type": media_type,
            "findings": findings,
            "summary": _collect_counts([findings]),
            "parser": "ocr_image",
        }

    if ext == ".pdf":
        import fitz
        from PIL import Image

        doc = fitz.open(stream=file_bytes, filetype="pdf")
        findings_bucket: list[list[dict[str, Any]]] = []
        sanitized_pages: list[str] = []
        redacted_images: list[Any] = []

        for page in doc:
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            page_image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            redacted, _, sanitized_text, findings = _sanitize_image(page_image, mode)
            redacted_images.append(redacted.convert("RGB"))
            sanitized_pages.append(sanitized_text)
            findings_bucket.append(findings)

        if not redacted_images:
            raise ValueError("Empty PDF document")

        output = io.BytesIO()
        redacted_images[0].save(output, format="PDF", save_all=True, append_images=redacted_images[1:])
        flattened_findings = [item for chunk in findings_bucket for item in chunk]
        return {
            "sanitized_text": "\n\n".join(sanitized_pages),
            "sanitized_original_bytes": output.getvalue(),
            "sanitized_original_ext": ".pdf",
            "sanitized_original_media_type": "application/pdf",
            "findings": flattened_findings,
            "summary": _collect_counts(findings_bucket),
            "parser": "pdf_ocr",
        }

    raise ValueError(f"Unsupported file type: {ext}")
