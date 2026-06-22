# Copyright 2021, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from requests import Session, adapters, models
from requests.structures import CaseInsensitiveDict
from typing import Any

import time

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

# Recycle pooled connections so a connection the API server has already closed is
# never written to (which would surface as a fatal RemoteDisconnected). The server
# bounds how long it keeps a connection open, both while idle and by total
# lifetime, so keep the client's reuse window below those. Two pool-wide bounds,
# both checked before a request is sent and enforced via the public
# PoolManager.clear():
#  - idle timeout (50s): recycle a connection idle longer than this
#  - max age (59m): recycle a connection older than this regardless of activity
DEFAULT_IDLE_TIMEOUT = 50.0
DEFAULT_MAX_AGE = 59 * 60.0


class AivenClientAdapter(adapters.HTTPAdapter):
    def __init__(
        self,
        *args: Any,
        timeout: int | None = None,
        idle_timeout: float | None = None,
        max_age: float | None = None,
        **kwargs: Any,
    ) -> None:
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.max_age = max_age
        now = time.monotonic()
        self._pools_created_at = now
        self._last_used_at = now
        super().__init__(*args, **kwargs)

    def _recycle_stale_connections(self) -> None:
        now = time.monotonic()
        recycle = (self.idle_timeout is not None and now - self._last_used_at >= self.idle_timeout) or (
            self.max_age is not None and now - self._pools_created_at >= self.max_age
        )
        if recycle:
            self.poolmanager.clear()
            for proxy in self.proxy_manager.values():
                proxy.clear()
            self._pools_created_at = now
        self._last_used_at = now

    def send(self, *args: Any, **kwargs: Any) -> models.Response:
        if not kwargs.get("timeout"):
            kwargs["timeout"] = self.timeout
        self._recycle_stale_connections()
        return super().send(*args, **kwargs)


def get_requests_session(
    *,
    timeout: int | None = None,
    idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
    max_age: float | None = DEFAULT_MAX_AGE,
) -> Session:
    adapter = AivenClientAdapter(timeout=timeout, idle_timeout=idle_timeout, max_age=max_age)

    session = Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = True
    session.headers.update(
        CaseInsensitiveDict(
            {
                "content-type": "application/json",
                "user-agent": "aiven-client/" + __version__,
            }
        )
    )

    return session
