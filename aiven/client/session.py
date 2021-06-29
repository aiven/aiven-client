from requests import adapters, Session
from requests.structures import CaseInsensitiveDict
from typing import Optional

try:
    from .version import __version__  # pylint: disable=no-name-in-module
except ImportError:
    __version__ = "UNKNOWN"


class AivenClientAdapter(adapters.HTTPAdapter):
    def __init__(self, *args, timeout: Optional[int] = None, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):  # pylint: disable=signature-differs
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
