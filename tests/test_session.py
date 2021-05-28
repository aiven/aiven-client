# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client.session import AivenClientAdapter, get_requests_session
from requests import Session

import pytest


def test_valid_requests_session():
    """Test that get_requests_session returns a valid Session that has the expected parameters set.
    """

    session = get_requests_session()

    assert isinstance(session, Session)
    assert "aiven-client" in session.headers["User-Agent"]

    adapter = session.adapters["https://"]
    assert isinstance(adapter, AivenClientAdapter)
    assert hasattr(adapter, "timeout")
    assert adapter.timeout is None


@pytest.mark.parametrize("argument,value", [
    ("timeout", 30),
    ("timeout", 0),
])
def test_adapter_parameters_are_passed_along(argument, value):
    session = get_requests_session(**{argument: value})
    adapter = session.adapters["https://"]
    assert isinstance(adapter, AivenClientAdapter)
    assert hasattr(adapter, argument)
    assert getattr(adapter, argument) == value
