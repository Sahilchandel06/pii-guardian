from __future__ import annotations

import re

SUPPORTED_MODES = {"mask", "redact", "tokenize"}


def _mask_value(entity_type: str, value: str) -> str:
    if entity_type == "EMAIL_ADDRESS" and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"

    if entity_type == "PHONE_NUMBER":
        digits = re.sub(r"\D", "", value)
        return f"{'*' * max(0, len(digits) - 2)}{digits[-2:]}"

    if entity_type == "IN_AADHAAR":
        digits = re.sub(r"\D", "", value)
        if len(digits) == 12:
            return f"XXXX XXXX {digits[-4:]}"

    if entity_type == "IN_VID":
        digits = re.sub(r"\D", "", value)
        if len(digits) == 16:
            return f"XXXX XXXX XXXX {digits[-4:]}"

    if entity_type == "DATE_OF_BIRTH":
        parts = re.split(r"[\/\-.]", value.strip())
        if len(parts) == 3 and parts[-1].isdigit():
            year = parts[-1][-4:]
            return f"XX/XX/{year}"
        return "[MASKED_DOB]"

    if entity_type == "IN_PAN" and len(value) == 10:
        return f"{value[:2]}****{value[-2:]}"

    if entity_type == "IP_ADDRESS":
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"

    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def sanitize_text(
    text: str,
    findings: list[dict],
    mode: str = "mask",
) -> tuple[str, dict[str, str]]:
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Supported modes: {', '.join(sorted(SUPPORTED_MODES))}")

    sanitized = text
    token_map: dict[str, str] = {}
    value_token_cache: dict[tuple[str, str], str] = {}
    token_counter = 1

    for item in sorted(findings, key=lambda x: x["start"], reverse=True):
        start = item["start"]
        end = item["end"]
        entity_type = item["entity_type"]
        original_value = sanitized[start:end]

        if mode == "redact":
            replacement = f"[REDACTED_{entity_type}]"
        elif mode == "tokenize":
            cache_key = (entity_type, original_value)
            if cache_key not in value_token_cache:
                value_token_cache[cache_key] = f"TOKEN_{entity_type}_{token_counter:04d}"
                token_counter += 1
            replacement = value_token_cache[cache_key]
            token_map[replacement] = original_value
        else:
            replacement = _mask_value(entity_type, original_value)

        sanitized = sanitized[:start] + replacement + sanitized[end:]

    return sanitized, token_map
