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

    # Mask IN_ADDRESS: partial masking - keep numbers, mask words
    if entity_type == "IN_ADDRESS":
        # Split into words, mask alphabetic words longer than 2 chars
        words = re.findall(r'\b\w+\b', value)
        masked_words = []
        for word in words:
            if word.isdigit():
                masked_words.append(word)
            elif len(word) > 2:
                masked_words.append(f"{word[0]}{'*' * (len(word) - 1)}")
            else:
                masked_words.append(word)
        return " ".join(masked_words)

    # Mask BANK_ACCOUNT: show first and last 2 digits
    if entity_type == "BANK_ACCOUNT":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return f"{digits[:2]}{'*' * (len(digits) - 4)}{digits[-2:]}"
        return "[MASKED_ACCOUNT]"

    if entity_type == "IFSC_CODE":
        value = value.strip().upper()
        if len(value) == 11:
            return f"{value[:4]}0******"
        return "[MASKED_IFSC]"

    if entity_type == "PASSPORT_NUMBER":
        value = value.strip().upper()
        if len(value) == 8:
            return f"{value[0]}******{value[-1]}"
        return "[MASKED_PASSPORT]"

    if entity_type in {"DEVICE_ID", "FINGERPRINT_TEMPLATE", "FACE_TEMPLATE"}:
        if len(value) <= 8:
            return "[MASKED_ID]"
        return f"{value[:4]}***{value[-3:]}"

    if entity_type == "BANK_NAME":
        return "[REDACTED_BANK]"

    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 10:
            return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"
        return "[MASKED_CARD]"

    # Mask UPI_ID: show first char of username, mask domain
    if entity_type == "UPI_ID" and "@" in value:
        username, domain = value.split("@", 1)
        masked_username = f"{username[:1]}{'*' * (len(username) - 1)}" if len(username) > 1 else username
        return f"{masked_username}@{domain}"

    # Mask PERSON_NAME: show first character, mask rest (e.g., "John Doe" -> "J*** D***")
    if entity_type == "PERSON_NAME":
        words = value.split()
        masked_words = []
        for word in words:
            if len(word) <= 1:
                masked_words.append(word)
            else:
                masked_words.append(f"{word[0]}{'*' * (len(word) - 1)}")
        return " ".join(masked_words)
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
