# Copyright 2023, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from aiven.client import AivenClient
from http import HTTPStatus
from typing import Any, Dict, Optional
from unittest import mock

import pytest


class MockResponse:
    def __init__(
        self, status_code: int, json_data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None
    ):
        self.status_code = status_code
        self.json_data = json_data
        self.headers = {} if headers is None else headers

    def json(self) -> Any:
        return self.json_data


@pytest.mark.parametrize(
    "response",
    [
        MockResponse(status_code=HTTPStatus.NO_CONTENT),
        MockResponse(status_code=HTTPStatus.CREATED, headers={"Content-Length": "0"}),
    ],
)
def test_no_content_returned_from_api(response: MockResponse) -> None:
    aiven_client = AivenClient("")
    with mock.patch("aiven.client.client.AivenClientBase._execute", return_value=response):
        assert aiven_client.verify(aiven_client.post, "/") == {}
        assert aiven_client.verify(aiven_client.patch, "/") == {}
        assert aiven_client.verify(aiven_client.put, "/") == {}
        assert aiven_client.verify(aiven_client.delete, "/") == {}
