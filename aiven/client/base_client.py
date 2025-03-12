# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from ._typing import assert_never
from .session import get_requests_session
from http import HTTPStatus
from requests import Response
from requests_toolbelt import MultipartEncoder  # type: ignore
from typing import Any, Callable, Final, Literal, Mapping, NamedTuple, TYPE_CHECKING, TypedDict
from urllib.parse import quote

import datetime
import json
import logging
import requests
import time

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    from typing_extensions import TypeAlias


HTTPMethod: TypeAlias = Literal[
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
]


class RetrySpec(NamedTuple):
    attempts: int = 3
    # Retry GET operations by default
    http_methods: tuple[HTTPMethod, ...] = ("GET",)
    sleep: datetime.timedelta = datetime.timedelta(milliseconds=200)


class AivenClientBase:
    """Aiven Client with low-level HTTP operations"""

    NO_RETRY: Final = RetrySpec(attempts=1)
    DEFAULT_RETRY: Final = RetrySpec()

    def __init__(
        self,
        base_url: str,
        show_http: bool = False,
        request_timeout: int | None = None,
        default_retry_spec: RetrySpec = DEFAULT_RETRY,
    ) -> None:
        self.log = logging.getLogger("AivenClient")
        self.auth_token: str | None = None
        self.base_url = base_url
        self.log.debug("using %r", self.base_url)
        self.session = get_requests_session(timeout=request_timeout)
        self.http_log = logging.getLogger("aiven_http")
        self.init_http_logging(show_http)
        self.api_prefix = "/v1"
        self.default_retry_spec: Final = default_retry_spec

    def init_http_logging(self, show_http: bool) -> None:
        http_handler = logging.StreamHandler()
        http_handler.setFormatter(logging.Formatter("%(message)s"))
        self.http_log.addHandler(http_handler)
        self.http_log.propagate = False
        self.http_log.setLevel(logging.INFO)
        if show_http:
            self.http_log.setLevel(logging.DEBUG)

    def set_auth_token(self, token: str) -> None:
        self.auth_token = token

    def set_ca(self, ca: str) -> None:
        self.session.verify = ca

    def _execute(self, func: Callable, method: str, path: str, body: Any, params: Any = None) -> Response:
        url = self.base_url + path
        headers = {}
        if isinstance(body, dict):
            headers["content-type"] = "application/json"
            data = json.dumps(body)
            log_data = json.dumps(body, sort_keys=True, indent=4)
        elif isinstance(body, MultipartEncoder):
            headers["content-type"] = body.content_type
            data = body
            log_data = data
        else:
            headers["content-type"] = "application/octet-stream"
            data = body
            log_data = data or ""

        if self.auth_token:
            headers["authorization"] = "aivenv1 {token}".format(token=self.auth_token)

        self.http_log.debug("-----Request Begin-----")
        self.http_log.debug("%s %s %s", method, url, params if params else "")
        for header, header_value in headers.items():
            self.http_log.debug("%s: %s", header, header_value)

        self.http_log.debug("")
        self.http_log.debug("%s", log_data)
        self.http_log.debug("-----Request End-----")

        response = func(url, headers=headers, params=params, data=data)

        self.http_log.debug("-----Response Begin-----")
        self.http_log.debug("%s %s", response.status_code, response.reason)
        for header, header_value in response.headers.items():
            self.http_log.debug("%s: %s", header, header_value)

        self.http_log.debug("")
        if response.headers.get("content-type") == "application/json":
            self.http_log.debug("%s", json.dumps(response.json(), sort_keys=True, indent=4))
        else:
            self.http_log.debug("%s", response.text)

        self.http_log.debug("-----Response End-----")

        if not str(response.status_code).startswith("2"):
            raise Error(response, status=response.status_code)

        return response

    def get(self, path: str = "", params: Any = None) -> Response:
        """HTTP GET"""
        return self._execute(self.session.get, "GET", path, body=None, params=params)

    def patch(self, path: str = "", body: Any = None, params: Any = None) -> Response:
        """HTTP PATCH"""
        return self._execute(self.session.patch, "PATCH", path, body, params)

    def post(self, path: str = "", body: Any = None, params: Any = None) -> Response:
        """HTTP POST"""
        return self._execute(self.session.post, "POST", path, body, params)

    def put(self, path: str = "", body: Any = None, params: Any = None) -> Response:
        """HTTP PUT"""
        return self._execute(self.session.put, "PUT", path, body, params)

    def delete(self, path: str = "", body: Any = None, params: Any = None) -> Response:
        """HTTP DELETE"""
        return self._execute(self.session.delete, "DELETE", path, body, params)

    def _get_retry_spec(
        self,
        op: Callable[..., Response],
        argument: int | RetrySpec | None,
    ) -> RetrySpec:
        if argument is None:
            if op.__name__.upper() in self.default_retry_spec.http_methods:
                return self.default_retry_spec
            else:
                return self.NO_RETRY
        elif isinstance(argument, int):
            return self.default_retry_spec._replace(attempts=argument)
        elif isinstance(argument, RetrySpec):
            return argument
        else:
            assert_never(argument)

    def verify(
        self,
        op: Callable[..., Response],
        path: str,
        body: Any = None,
        params: Any = None,
        result_key: str | None = None,
        retry: int | RetrySpec | None = None,
    ) -> Any:
        retry_spec = self._get_retry_spec(op, retry)
        attempts = retry_spec.attempts
        path = self.api_prefix + path

        while attempts:
            attempts -= 1
            try:
                if body is not None:
                    response = op(path=path, body=body, params=params)
                else:
                    response = op(path=path, params=params)
                break
            except requests.exceptions.ConnectionError as ex:
                if attempts <= 0:
                    raise
                self.log.warning(
                    "%s %s failed: %s: %s; retrying in 0.2 seconds, %s attempts left",
                    op.__name__.upper(),
                    path,
                    ex.__class__.__name__,
                    ex,
                    attempts,
                )
                time.sleep(retry_spec.sleep.total_seconds())

        return self._process_response(response=response, op=op, path=path, result_key=result_key)

    @staticmethod
    def build_path(*parts: str) -> str:
        return "/" + "/".join(quote(part, safe="") for part in parts)

    def _process_response(
        self,
        response: Response,
        op: Callable[..., Response],
        path: str,
        result_key: str | None = None,
    ) -> Mapping | bytes:
        # Check API is actually returning data or not
        if response.status_code == HTTPStatus.NO_CONTENT or len(response.content) == 0:
            return {}

        if response.headers.get("Content-Type") == "application/octet-stream":
            return response.content

        result = response.json()

        if result.get("error"):
            raise ResponseError(
                "server returned error: {op} {base_url}{path} {result}".format(
                    op=op.__doc__, base_url=self.base_url, path=path, result=result
                )
            )

        if result_key is not None:
            return result[result_key]
        return result


class Error(Exception):
    """Request error"""

    def __init__(self, response: Response, status: int = 520) -> None:
        Exception.__init__(self, response.text, status)
        self.response = response
        self.status = status

    def __str__(self) -> str:
        response_text, status = self.args
        return f"{response_text}, status({type(status)})={str(status)}"


class ResponseError(Exception):
    """Server returned error message"""


class Tag(TypedDict):
    key: str
    value: str
