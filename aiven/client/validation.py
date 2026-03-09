# Copyright 2024, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""Input validation for resource identifiers.

Rejects patterns commonly produced by LLM hallucinations:
path traversal, percent-encoded segments, embedded query params,
control characters, and empty/whitespace-only strings.
"""

from __future__ import annotations

import re
import unicodedata

# Control characters (U+0000 to U+001F and U+007F)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# Percent-encoded sequences (e.g., %2e, %2f)
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")

# Embedded query string or fragment
_QUERY_FRAGMENT_RE = re.compile(r"[?#]")


def validate_resource_id(value: str, field_name: str) -> str:
    """Validate a resource identifier against common hallucination patterns.

    Raises ValueError if the value contains dangerous patterns.
    Returns the value unchanged if valid.
    """
    if not value or not value.strip():
        raise ValueError(f"Invalid resource identifier for {field_name!r}: must not be empty")

    # Normalize Unicode to catch fullwidth character bypasses (e.g. ．．/ -> ../)
    value = unicodedata.normalize("NFKC", value)

    if ".." in value:
        raise ValueError(f"Invalid resource identifier for {field_name!r}: " f"path traversal sequence '..' is not allowed")

    if _PERCENT_ENCODED_RE.search(value):
        raise ValueError(f"Invalid resource identifier for {field_name!r}: " f"percent-encoded characters are not allowed")

    if _QUERY_FRAGMENT_RE.search(value):
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: " f"query parameters '?' and fragments '#' are not allowed"
        )

    if _CONTROL_CHAR_RE.search(value):
        raise ValueError(f"Invalid resource identifier for {field_name!r}: " f"control characters are not allowed")

    return value
