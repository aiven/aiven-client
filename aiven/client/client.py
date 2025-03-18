# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations
from aiven.client.account_client import AivenAccountOrganisationClient

from aiven.client.common_client import AivenCommonClient
from aiven.client.opensearch_client import AivenOpenSearchClient
from typing import TYPE_CHECKING

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass

UNCHANGED = object()  # used as a sentinel value


class AivenClient(
    AivenCommonClient,
    AivenAccountOrganisationClient,
    AivenOpenSearchClient,
):
    pass
