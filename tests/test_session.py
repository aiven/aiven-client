# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.session import DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_AGE, AivenClientAdapter, get_requests_session
from requests import Session
from typing import Any

import pytest


def test_valid_requests_session() -> None:
    """Test that get_requests_session returns a valid Session that has the expected parameters set."""

    session = get_requests_session()

    assert isinstance(session, Session)
    assert "aiven-client" in session.headers["User-Agent"]

    adapter = session.adapters["https://"]
    assert isinstance(adapter, AivenClientAdapter)
    assert hasattr(adapter, "timeout")
    assert adapter.timeout is None
    assert adapter.idle_timeout == DEFAULT_IDLE_TIMEOUT
    assert adapter.max_age == DEFAULT_MAX_AGE


@pytest.mark.parametrize(
    "argument,value",
    [
        ("timeout", 30),
        ("timeout", 0),
        ("idle_timeout", 10.0),
        ("idle_timeout", None),
        ("max_age", 120.0),
        ("max_age", None),
    ],
)
def test_adapter_parameters_are_passed_along(argument: str, value: Any) -> None:
    kwargs: dict[str, Any] = {argument: value}
    session = get_requests_session(**kwargs)
    adapter = session.adapters["https://"]
    assert isinstance(adapter, AivenClientAdapter)
    assert hasattr(adapter, argument)
    assert getattr(adapter, argument) == value
