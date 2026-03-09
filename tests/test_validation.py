# Copyright 2024, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

import pytest

from aiven.client.validation import validate_resource_id


class TestValidateResourceId:
    """Resource IDs must reject agent hallucination patterns."""

    @pytest.mark.parametrize(
        "valid_id",
        [
            "my-service",
            "my_service_123",
            "ProductionDB",
            "pg-us-east-1",
            "a",
            "service-with.dot",
        ],
    )
    def test_accepts_valid_ids(self, valid_id: str) -> None:
        validate_resource_id(valid_id, "service_name")

    @pytest.mark.parametrize(
        "bad_id,reason",
        [
            ("../etc/passwd", "path traversal"),
            ("..%2f..%2fetc", "percent-encoded traversal"),
            ("service?admin=true", "embedded query param"),
            ("service#fragment", "embedded fragment"),
            ("service\x00name", "null byte"),
            ("service\nname", "newline"),
            ("service\tname", "tab"),
            ("%2e%2e/secret", "percent-encoded dots"),
            ("", "empty string"),
            ("   ", "whitespace only"),
        ],
    )
    def test_rejects_dangerous_ids(self, bad_id: str, reason: str) -> None:
        with pytest.raises(ValueError, match="Invalid resource identifier"):
            validate_resource_id(bad_id, "service_name")
