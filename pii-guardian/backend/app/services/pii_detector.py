import re
import os
from collections import defaultdict
from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer


# previously guarded by environment flag; we always attempt to use Presidio when available
# leaving a flag for optional disable but defaulting to true for combined mode
USE_PRESIDIO = os.getenv("USE_PRESIDIO", "true").lower() == "true"
USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"
# if true we will attempt to call a language model; config controls which
USE_LLM_OPEN_SOURCE = os.getenv("USE_LLM_OPEN_SOURCE", "false").lower() == "true"
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
    """Returns a singleton analyzer instance.

    We ignore the USE_PRESIDIO flag here so that regex and Presidio
    always run together.  The flag can still be set to "false" to
    explicitly *disable* the analyzer, but by default it is enabled and
    any build errors are caught gracefully.
    """
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

FALLBACK_PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    # Aadhaar and VID with ASCII/Devanagari/Gujarati digits.
    "IN_AADHAAR": re.compile(r"\b[0-9०-९૦-૯]{4}[-\s]?[0-9०-९૦-૯]{4}[-\s]?[0-9०-९૦-૯]{4}\b"),
    "IN_VID": re.compile(
        r"\b(?:VID|વિઆઈડી|विड)\s*[:\-]?\s*[0-9०-९૦-૯]{4}[-\s]?[0-9०-९૦-૯]{4}[-\s]?[0-9०-९૦-૯]{4}[-\s]?[0-9०-९૦-૯]{4}\b",
        re.IGNORECASE,
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:DOB|D\.O\.B|Date\s*of\s*Birth|जन्म\s*तिथि|જન્મ\s*તારીખ)?\s*[:\-]?\s*[0-3०-३૦-૩][0-9०-९૦-૯][\/\-\.][0-1०-१૦-૧][0-9०-९૦-૯][\/\-\.][1-2१२][0-9०-९૦-૯]{3}\b",
        re.IGNORECASE,
    ),
    "PERSON_NAME": re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b"),
    "PERSON_NAME_INDIC": re.compile(
        r"(?:नाम|Name|નામ)\s*[:\-]?\s*([ऀ-ॿ઀-૿]{2,}(?:\s+[ऀ-ॿ઀-૿]{2,}){0,3})",
        re.IGNORECASE,
    ),
    # Standalone Hindi names: 2+ words in Devanagari script (3+ chars each word)
    "PERSON_NAME_HINDI": re.compile(r"[\u0900-\u097F]{3,}(?:\s+[\u0900-\u097F]{3,})+"),
    # Standalone Gujarati names: 2+ words in Gujarati script (3+ chars each word)
    "PERSON_NAME_GUJARATI": re.compile(r"[\u0A80-\u0AFF]{3,}(?:\s+[\u0A80-\u0AFF]{3,})+"),
    "IN_ADDRESS": re.compile(
        r"\b\d{1,4}\s+[A-Za-z0-9\s,.-]*(Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Nagar|Colony|Sector|Block|Sector)\b",
        re.IGNORECASE,
    ),
    "IN_ADDRESS_INDIC": re.compile(
        r"(?:पता|સરનામું|Address)\s*[:\-]?\s*[ऀ-ॿ઀-૿0-9A-Za-z\s,./-]{8,}",
        re.IGNORECASE,
    ),
    # Indian PIN code (6 digits) often appears in addresses
    "PIN_CODE": re.compile(r"\b[0-9]{6}\b"),
    # generic Indian bank account numbers (9-18 digits, may include spaces)
    "BANK_ACCOUNT": re.compile(r"\b\d[\d\s]{7,16}\d\b"),
    # UPI ID (Unified Payments Interface) - username@handle
    "UPI_ID": re.compile(r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b"),
}

PRESIDIO_ENTITY_MAP = {
    "PERSON": "PERSON_NAME",
    "LOCATION": "IN_ADDRESS",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "IP_ADDRESS": "IP_ADDRESS",
    "IN_PAN": "IN_PAN",
    "IN_AADHAAR": "IN_AADHAAR",
    "DATE_TIME": "DATE_OF_BIRTH",
    "IN_ADDRESS": "IN_ADDRESS",
}

FALLBACK_ENTITY_MAP = {
    "PERSON_NAME_ENGLISH": "PERSON_NAME",
    "PERSON_NAME_HINDI": "PERSON_NAME",
    "PERSON_NAME_GUJARATI": "PERSON_NAME",
    "IN_ADDRESS_INDIC": "IN_ADDRESS",
    "PIN_CODE": "IN_ADDRESS",
}

# Whitelist of common words to exclude from PII detection
PII_WHITELIST = {
    "john", "doe", "smith", "apple", "google", "microsoft", "amazon", "facebook",
    "india", "delhi", "mumbai", "ahmedabad", "gujarat", "rajasthan", "maharashtra",
    # Add more common non-PII words as needed
}


def _add_finding(findings: list[dict[str, Any]], keyset: set[tuple[int, int, str]], finding: dict[str, Any]) -> None:
    key = (finding["start"], finding["end"], finding["entity_type"])
    if key not in keyset:
        # Check whitelist to avoid false positives
        value_lower = finding["value"].lower().strip()
        if value_lower in PII_WHITELIST:
            return  # Skip whitelisted words
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
                # Add confidence threshold to reduce false positives
                if float(result.score) >= 0.7:  # Only accept high-confidence matches
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

    findings.sort(key=lambda item: (item["start"], item["end"]))

    # optionally augment with an LLM service
    if USE_LLM and text.strip():
        try:
            llm_hits = _run_llm(text)
            for hit in llm_hits:
                _add_finding(findings, keyset, hit)
        except Exception:
            pass
        findings.sort(key=lambda item: (item["start"], item["end"]))
    return findings


def _run_llm(text: str) -> list[dict[str, Any]]:
    """Extract PII spans using either OpenAI or an open-source model.

    The function returns a list of dictionaries with start/end offsets,
    entity_type and value, just like the regex/Presidio pipeline produces.
    """
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
        # open-source path: use langchain with Oolama or a local transformers model
        try:
            from langchain.llms import Oolama
            # use llama by default, which is freely available via Oolama
            llm_name = os.getenv("OOLAMA_MODEL", "llama")
            llm = Oolama(model=llm_name)
            output = llm(prompt)
        except ImportError:
            # fallback to transformers if langchain not available
            from transformers import pipeline
            model_name = os.getenv("LLM_MODEL", "google/flan-t5-small")
            gen = pipeline("text2text-generation", model=model_name, device=0 if torch.cuda.is_available() else -1)
            result = gen(prompt, max_length=1024, do_sample=False)
            output = result[0]["generated_text"]
    else:
        from openai import OpenAI

        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        output = response.choices[0].message.content

    try:
        return json.loads(output)
    except Exception:
        return []


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in findings:
        counts[item["entity_type"]] += 1
    return dict(counts)
