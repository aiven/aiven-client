# Copyright 2021, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from requests import adapters, models, Session
from requests.structures import CaseInsensitiveDict
from typing import Any

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"


class AivenClientAdapter(adapters.HTTPAdapter):
    def __init__(self, *args: Any, timeout: int | None = None, **kwargs: Any) -> None:
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args: Any, **kwargs: Any) -> models.Response:
        if not kwargs.get("timeout"):
            kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


def get_requests_session(*, timeout: int | None = None) -> Session:
    adapter = AivenClientAdapter(timeout=timeout)

    session = Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = True
    session.headers = CaseInsensitiveDict(
        {
            "content-type": "application/json",
            "user-agent": "aiven-client/" + __version__,
        }
    )

    return session
