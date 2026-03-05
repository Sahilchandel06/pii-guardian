import re
import os
from collections import defaultdict
from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer


USE_PRESIDIO = os.getenv("USE_PRESIDIO", "false").lower() == "true"
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
    if not USE_PRESIDIO:
        return None
    if _analyzer is not None:
        return _analyzer
    try:
        _analyzer = _build_analyzer()
    except Exception:
        _analyzer = None
    return _analyzer

FALLBACK_PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "IN_AADHAAR": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "PERSON_NAME": re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b"),
    "IN_ADDRESS": re.compile(
        r"\b\d{1,4}\s+[A-Za-z0-9\s,.-]*(Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Nagar|Colony|Sector)\b"
    ),
}

PRESIDIO_ENTITY_MAP = {
    "PERSON": "PERSON_NAME",
    "LOCATION": "IN_ADDRESS",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "IP_ADDRESS": "IP_ADDRESS",
    "IN_PAN": "IN_PAN",
    "IN_AADHAAR": "IN_AADHAAR",
    "IN_ADDRESS": "IN_ADDRESS",
}


def _add_finding(findings: list[dict[str, Any]], keyset: set[tuple[int, int, str]], finding: dict[str, Any]) -> None:
    key = (finding["start"], finding["end"], finding["entity_type"])
    if key not in keyset:
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
            # Fallback regex scanning still enforces core hackathon detection requirements.
            pass

    for entity_type, pattern in FALLBACK_PATTERNS.items():
        for match in pattern.finditer(text):
            _add_finding(
                findings,
                keyset,
                {
                    "start": match.start(),
                    "end": match.end(),
                    "entity_type": entity_type,
                    "score": 0.5,
                    "value": match.group(0),
                    "source": "regex",
                },
            )

    findings.sort(key=lambda item: (item["start"], item["end"]))
    return findings


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in findings:
        counts[item["entity_type"]] += 1
    return dict(counts)
