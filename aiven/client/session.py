from requests import adapters, models, Session
from requests.structures import CaseInsensitiveDict
from typing import Any, Optional

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"


class AivenClientAdapter(adapters.HTTPAdapter):
    def __init__(self, *args: Any, timeout: Optional[int] = None, **kwargs: Any) -> None:
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args: Any, **kwargs: Any) -> models.Response:  # pylint: disable=signature-differs
        if not kwargs.get("timeout"):
            kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


def get_requests_session(*, timeout: Optional[int] = None) -> Session:
    adapter = AivenClientAdapter(timeout=timeout)

    session = Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = True
    session.headers = CaseInsensitiveDict({
        "content-type": "application/json",
        "user-agent": "aiven-client/" + __version__,
    })

    return session
