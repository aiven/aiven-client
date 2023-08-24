# Copyright 2023, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client import AivenClient
from aiven.client.client import ResponseError
from http import HTTPStatus
from typing import Any
from unittest import mock

import json
import pytest


class MockResponse:
    def __init__(
        self,
        status_code: int,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ):
        self.status_code = status_code
        self.json_data = json_data
        if content is not None:
            self.content = content
        elif json_data is not None:
            self.content = json.dumps(json_data).encode("utf-8")
        else:
            self.content = b""
        self.headers = {} if headers is None else headers
        self.text = self.content.decode("utf-8")

    def json(self) -> Any:
        return self.json_data


@pytest.mark.parametrize(
    "response",
    [
        MockResponse(status_code=HTTPStatus.NO_CONTENT),
        MockResponse(status_code=HTTPStatus.CREATED),
    ],
)
def test_no_content_returned_from_api(response: MockResponse) -> None:
    aiven_client = AivenClient("")
    with mock.patch("aiven.client.client.AivenClientBase._execute", return_value=response):
        assert aiven_client.verify(aiven_client.post, "/") == {}
        assert aiven_client.verify(aiven_client.patch, "/") == {}
        assert aiven_client.verify(aiven_client.put, "/") == {}
        assert aiven_client.verify(aiven_client.delete, "/") == {}


@pytest.mark.parametrize(
    "response,expected_result",
    [
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/octet-stream"},
                content=b"foo",
            ),
            b"foo",
        ),
        (
            MockResponse(status_code=HTTPStatus.OK, headers={"Content-Type": "application/json"}, json_data={}),
            {},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/json"},
                json_data={},
                content=b"foo",
            ),
            {},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/json"},
                json_data={"foo": "bar"},
                content=b"foo",
            ),
            {"foo": "bar"},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/octet-stream"},
                json_data={"foo": "bar"},
                content=b"foo",
            ),
            b"foo",
        ),
    ],
)
def test_response_processing(response: MockResponse, expected_result: Any) -> None:
    def operation() -> MockResponse:
        return response

    aiven_client = AivenClient("")
    assert aiven_client._process_response(response=response, op=operation, path="") == expected_result  # type: ignore


def test_response_processing_result_key() -> None:
    expected_value = 2
    response = MockResponse(
        status_code=HTTPStatus.OK,
        headers={"Content-Type": "application/json"},
        json_data={"foo": 1, "bar": expected_value, "spam": 3},
    )

    def operation() -> MockResponse:
        return response

    aiven_client = AivenClient("")
    assert (
        aiven_client._process_response(response=response, op=operation, path="", result_key="bar")  # type: ignore
        == expected_value
    )


def test_response_processing_error_raise() -> None:
    response = MockResponse(
        status_code=HTTPStatus.OK,
        headers={"Content-Type": "application/json"},
        json_data={"foo": 1, "bar": 2, "spam": 3, "error": "test error"},
    )

    def operation() -> MockResponse:
        """test operation"""
        return response

    aiven_client = AivenClient("test_base_url")

    with pytest.raises(ResponseError) as e:
        aiven_client._process_response(response=response, op=operation, path="", result_key="bar")  # type: ignore
        assert (
            str(e)
            == "server returned error: test operation test_base_url {'foo': 1, 'bar': 2, 'spam': 3, 'error': 'test error'}"
        )
