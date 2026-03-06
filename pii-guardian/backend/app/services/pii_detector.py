import json
import os
import re
from collections import defaultdict
from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer


USE_PRESIDIO = os.getenv("USE_PRESIDIO", "true").lower() == "true"
USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"
USE_LLM_OPEN_SOURCE = os.getenv("USE_LLM_OPEN_SOURCE", "false").lower() == "true"
REQUIRE_AADHAAR_VERHOEFF = os.getenv("REQUIRE_AADHAAR_VERHOEFF", "false").lower() == "true"
_analyzer: AnalyzerEngine | None = None


def _build_analyzer() -> AnalyzerEngine:
    analyzer = AnalyzerEngine()

    pan_recognizer = PatternRecognizer(
        supported_entity="IN_PAN",
        patterns=[Pattern("pan_pattern", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.8)],
    )
    aadhaar_recognizer = PatternRecognizer(
        supported_entity="IN_AADHAAR",
        patterns=[Pattern("aadhaar_pattern", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.85)],
    )
    address_recognizer = PatternRecognizer(
        supported_entity="IN_ADDRESS",
        patterns=[
            Pattern(
                "address_pattern",
                r"\b\d{1,4}\s+[A-Za-z0-9\s,.-]*(Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Nagar|Colony|Sector)\b",
                0.55,
            )
        ],
    )

    analyzer.registry.add_recognizer(pan_recognizer)
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    analyzer.registry.add_recognizer(address_recognizer)
    return analyzer


def _get_analyzer() -> AnalyzerEngine | None:
    global _analyzer
    if _analyzer is not None:
        return _analyzer
    if not USE_PRESIDIO:
        return None
    try:
        _analyzer = _build_analyzer()
    except Exception:
        _analyzer = None
    return _analyzer


FALLBACK_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "IN_AADHAAR": re.compile(
        r"\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
    ),
    "IN_VID": re.compile(
        r"\bVID\s*[:\-]?\s*[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b",
        re.IGNORECASE,
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:DOB|D\.O\.B|Date\s*of\s*Birth)?\s*[:\-]?\s*[0-3][0-9][\/\-\.][0-1][0-9][\/\-\.][1-2][0-9]{3}\b",
        re.IGNORECASE,
    ),
    "DATE_OF_BIRTH_TEXT": re.compile(
        r"\b(?:DOB|D\.O\.B|Date\s*of\s*Birth)?\s*[:\-]?\s*(?:0?[1-9]|[12][0-9]|3[01])\s+"
        r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
        r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+[12][0-9]{3}\b",
        re.IGNORECASE,
    ),
    "PERSON_NAME": re.compile(r"\b[A-Z][a-z]{1,24}(?: [A-Z][a-z]{1,24}){1,2}\b"),
    "IN_ADDRESS": re.compile(
        r"\b\d{1,4}\s+[A-Za-z0-9 ,.-]*(Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Nagar|Colony|Sector|Block)\b",
        re.IGNORECASE,
    ),
    "IN_ADDRESS_LABELLED": re.compile(r"Address\s*[:\-]?\s*[^\n]{8,}", re.IGNORECASE),
    "PIN_CODE": re.compile(r"\b[0-9]{6}\b"),
    "UPI_ID": re.compile(
        r"\b[a-zA-Z0-9._-]{2,}@(upi|okaxis|oksbi|okhdfcbank|okicici|okpnb|paytm|ybl|ibl|axl)\b",
        re.IGNORECASE,
    ),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "PASSPORT_NUMBER": re.compile(r"\b[A-PR-WYa-pr-wy][1-9][0-9]{6}\b"),
    "BANK_ACCOUNT": re.compile(r"\b[0-9]{11,18}\b"),
    "IFSC_CODE": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "DEVICE_ID": re.compile(r"\b(?:android|ios)-[a-zA-Z0-9]{6,}\b", re.IGNORECASE),
    "FINGERPRINT_TEMPLATE": re.compile(r"\bfp_hash_[a-zA-Z0-9]{6,}\b", re.IGNORECASE),
    "FACE_TEMPLATE": re.compile(r"\bface_tmp_[a-zA-Z0-9]{6,}\b", re.IGNORECASE),
    "BANK_NAME": re.compile(r"\b(?:HDFC|ICICI|SBI|AXIS|KOTAK|PNB|BOB|CANARA|IDFC)\s+Bank\b", re.IGNORECASE),
}

PRESIDIO_ENTITY_MAP = {
    "PERSON": "PERSON_NAME",
    "LOCATION": "IN_ADDRESS",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "IP_ADDRESS": "IP_ADDRESS",
    "IN_PAN": "IN_PAN",
    "IN_AADHAAR": "IN_AADHAAR",
    "CREDIT_CARD": "CREDIT_CARD",
    "DATE_TIME": "DATE_OF_BIRTH",
    "IN_ADDRESS": "IN_ADDRESS",
}

FALLBACK_ENTITY_MAP = {
    "IN_ADDRESS_LABELLED": "IN_ADDRESS",
    "PIN_CODE": "IN_ADDRESS",
    "DATE_OF_BIRTH_TEXT": "DATE_OF_BIRTH",
}

PII_WHITELIST = {
    "john", "doe", "smith", "apple", "google", "microsoft", "amazon", "facebook",
    "india", "delhi", "mumbai", "ahmedabad", "gujarat", "rajasthan", "maharashtra",
}
PERSON_LABEL_STOPWORDS = {
    "face", "template", "device", "id", "bank", "account", "passport",
    "aadhaar", "pan", "ifsc", "fingerprint", "mobile", "email", "address", "dob", "ip",
}

ENTITY_PRIORITY = {
    "IN_AADHAAR": 1,
    "CREDIT_CARD": 1,
    "BANK_ACCOUNT": 1,
    "IFSC_CODE": 1,
    "IN_PAN": 1,
    "PASSPORT_NUMBER": 1,
    "EMAIL_ADDRESS": 2,
    "PHONE_NUMBER": 2,
    "UPI_ID": 2,
    "IP_ADDRESS": 2,
    "DATE_OF_BIRTH": 2,
    "DEVICE_ID": 2,
    "FINGERPRINT_TEMPLATE": 2,
    "FACE_TEMPLATE": 2,
    "IN_ADDRESS": 3,
    "BANK_NAME": 3,
    "PERSON_NAME": 5,
}

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def _is_valid_verhoeff(number: str) -> bool:
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _is_valid_aadhaar(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) != 12:
        return False
    if digits[0] in {"0", "1"}:
        return False
    return _is_valid_verhoeff(digits)


def _is_valid_luhn(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) < 13 or len(digits) > 19:
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    should_double = False
    for ch in reversed(digits):
        d = int(ch)
        if should_double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        should_double = not should_double
    return total % 10 == 0


def _is_valid_finding(finding: dict[str, Any]) -> bool:
    value = str(finding.get("value", "")).strip()
    entity = finding.get("entity_type")
    if not value:
        return False

    value_lower = value.lower()
    if value_lower in PII_WHITELIST:
        return False

    if entity == "PERSON_NAME":
        if any(ch.isdigit() for ch in value):
            return False
        words = value.split()
        if len(words) < 2 or len(words) > 4:
            return False
        if any(word.lower() in PERSON_LABEL_STOPWORDS for word in words):
            return False

    if entity == "IN_ADDRESS" and len(value) < 8:
        return False

    if entity == "IP_ADDRESS" and not _valid_ipv4(value):
        return False

    if entity == "IN_AADHAAR":
        digits = _digits_only(value)
        if len(digits) != 12:
            return False
        if REQUIRE_AADHAAR_VERHOEFF and not _is_valid_aadhaar(value):
            return False

    if entity == "BANK_ACCOUNT":
        digits = _digits_only(value)
        if len(digits) < 11 or len(digits) > 18:
            return False
        if len(digits) == 12 and _is_valid_aadhaar(digits):
            return False
        if _is_valid_luhn(digits):
            return False

    if entity == "IFSC_CODE" and not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", value.upper()):
        return False

    if entity == "PASSPORT_NUMBER" and not re.fullmatch(r"[A-PR-WY][1-9][0-9]{6}", value.upper()):
        return False

    if entity == "CREDIT_CARD" and not _is_valid_luhn(value):
        return False

    if entity == "DATE_OF_BIRTH":
        numeric_ok = bool(re.search(r"[\/\-.]", value)) and len(re.split(r"[\/\-.]", value)) == 3
        text_ok = bool(
            re.search(
                r"(?:0?[1-9]|[12][0-9]|3[01])\s+"
                r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
                r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+[12][0-9]{3}",
                value,
                flags=re.IGNORECASE,
            )
        )
        if not (numeric_ok or text_ok):
            return False

    return True


def _finding_key(item: dict[str, Any]) -> tuple[int, float, int]:
    priority = ENTITY_PRIORITY.get(item.get("entity_type", ""), 10)
    score = float(item.get("score", 0.0))
    length = int(item.get("end", 0)) - int(item.get("start", 0))
    return (priority, -score, -length)


def _resolve_overlaps(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []

    for finding in sorted(findings, key=lambda item: (item["start"], item["end"])):
        replaced = False
        for idx, kept in enumerate(selected):
            overlaps = finding["start"] < kept["end"] and kept["start"] < finding["end"]
            if not overlaps:
                continue
            if _finding_key(finding) < _finding_key(kept):
                selected[idx] = finding
            replaced = True
            break
        if not replaced:
            selected.append(finding)

    selected.sort(key=lambda item: (item["start"], item["end"]))
    return selected


def _add_finding(findings: list[dict[str, Any]], keyset: set[tuple[int, int, str]], finding: dict[str, Any]) -> None:
    if not _is_valid_finding(finding):
        return
    key = (finding["start"], finding["end"], finding["entity_type"])
    if key in keyset:
        return
    keyset.add(key)
    findings.append(finding)


def detect_pii(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    keyset: set[tuple[int, int, str]] = set()

    analyzer = _get_analyzer()
    if analyzer is not None:
        try:
            results = analyzer.analyze(
                text=text,
                language="en",
                entities=list(PRESIDIO_ENTITY_MAP.keys()),
            )
            for result in results:
                if float(result.score) >= 0.7:
                    entity = PRESIDIO_ENTITY_MAP.get(result.entity_type, result.entity_type)
                    _add_finding(
                        findings,
                        keyset,
                        {
                            "start": result.start,
                            "end": result.end,
                            "entity_type": entity,
                            "score": float(result.score),
                            "value": text[result.start : result.end],
                            "source": "presidio",
                        },
                    )
        except Exception:
            pass

    for entity_type, pattern in FALLBACK_PATTERNS.items():
        normalized_entity = FALLBACK_ENTITY_MAP.get(entity_type, entity_type)
        for match in pattern.finditer(text):
            _add_finding(
                findings,
                keyset,
                {
                    "start": match.start(),
                    "end": match.end(),
                    "entity_type": normalized_entity,
                    "score": 0.5,
                    "value": match.group(0),
                    "source": "regex",
                },
            )

    findings = _resolve_overlaps(findings)

    if USE_LLM and text.strip():
        try:
            llm_hits = _run_llm(text)
            for hit in llm_hits:
                _add_finding(findings, keyset, hit)
        except Exception:
            pass
        findings = _resolve_overlaps(findings)
    return findings


def _run_llm(text: str) -> list[dict[str, Any]]:
    prompt = (
        "Extract only obvious personally identifiable information (PII) from the "
        "following text. Focus on: names, addresses, phone numbers, emails, "
        "identification numbers (like Aadhaar, PAN), bank accounts, dates of birth. "
        "Ignore generic words, company names, or ambiguous terms. "
        "Return a JSON array where each entry has keys "
        "\"start\", \"end\", \"entity_type\", and \"value\". "
        "Offsets should refer to the original input string. "
        "If no clear PII is found, return an empty array []."
        "\n\nText:\n" + text
    )

    if USE_LLM_OPEN_SOURCE:
        output = ""
        try:
            try:
                from langchain_community.llms import Ollama  # type: ignore
            except Exception:
                from langchain.llms import Ollama  # type: ignore
            llm_name = os.getenv("OLLAMA_MODEL", "llama3.1")
            llm = Ollama(model=llm_name)
            output = llm(prompt)
        except Exception:
            try:
                from transformers import pipeline
                try:
                    import torch  # type: ignore
                    device = 0 if torch.cuda.is_available() else -1
                except Exception:
                    device = -1
                model_name = os.getenv("LLM_MODEL", "google/flan-t5-small")
                gen = pipeline("text2text-generation", model=model_name, device=device)
                result = gen(prompt, max_length=1024, do_sample=False)
                output = result[0]["generated_text"]
            except Exception:
                return []
    else:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            output = response.choices[0].message.content or "[]"
        except Exception:
            return []

    parsed = _parse_llm_json(output)
    normalized: list[dict[str, Any]] = []
    for item in parsed:
        try:
            start = int(item["start"])
            end = int(item["end"])
            entity = str(item["entity_type"]).strip()
            value = str(item.get("value", ""))
        except Exception:
            continue
        if start < 0 or end <= start or end > len(text):
            continue
        normalized.append(
            {
                "start": start,
                "end": end,
                "entity_type": entity,
                "score": 0.6,
                "value": value or text[start:end],
                "source": "llm",
            }
        )
    return normalized


def _parse_llm_json(output: str) -> list[dict[str, Any]]:
    candidate = (output or "").strip()
    if not candidate:
        return []
    if "```" in candidate:
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", candidate, flags=re.DOTALL | re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
    try:
        parsed = json.loads(candidate)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in findings:
        counts[item["entity_type"]] += 1
    return dict(counts)
