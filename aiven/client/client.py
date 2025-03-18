# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.account_client import AivenAccountOrganisationClient
from aiven.client.clickhouse_client import AivenClickhouseClient
from aiven.client.common_client import AivenCommonClient
from aiven.client.opensearch_client import AivenOpenSearchClient
from aiven.client.privatelink_client import AivenPrivateLinkClient
from aiven.client.sustainability_client import AivenSustainabilityClient
from aiven.client.user_client import AivenUserClient
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
    AivenClickhouseClient,
    AivenOpenSearchClient,
    AivenPrivateLinkClient,
    AivenSustainabilityClient,
    AivenUserClient,
):
    pass
