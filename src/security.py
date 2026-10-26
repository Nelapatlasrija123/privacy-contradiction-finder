"""Security and privacy defense utilities for Privacy Contradiction Finder.

Includes secrets redaction, API key masking, and input boundary validation.
"""

from __future__ import annotations

import re


def mask_api_key(api_key: str | None) -> str:
    """Mask an API key for safe display in logs or UI without exposing secrets.

    Example:
        'AIzaSyB1234567890abcdef' -> 'AIza...cdef'
    """
    if not api_key:
        return "[NOT CONFIGURED]"

    clean_key = api_key.strip()
    if len(clean_key) <= 8:
        return "****"

    prefix = clean_key[:4]
    suffix = clean_key[-4:]
    return f"{prefix}...{suffix}"


def sanitize_log_message(message: str, secrets: list[str] | None = None) -> str:
    """Sanitize log messages to prevent accidental leakage of sensitive tokens or API keys."""
    if not message:
        return ""

    sanitized = message
    if secrets:
        for secret in secrets:
            if secret and len(secret) >= 6:
                sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")

    # Mask standard patterns that resemble API keys or tokens
    sanitized = re.sub(r"(AIza[0-9A-Za-z-_]{35})", "[REDACTED_GEMINI_KEY]", sanitized)
    sanitized = re.sub(r"(sk-[0-9A-Za-z-_]{32,})", "[REDACTED_OPENAI_KEY]", sanitized)

    return sanitized
