# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Mapping, TYPE_CHECKING

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass


class AivenClickhouseClient(AivenClientBase):
    def clickhouse_database_create(
        self,
        project: str,
        service: str,
        database: str,
    ) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "clickhouse",
            "db",
        )
        return self.verify(self.post, path, body={"database": database})

    def clickhouse_database_delete(
        self,
        project: str,
        service: str,
        database: str,
    ) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "clickhouse",
            "db",
            database,
        )
        return self.verify(self.delete, path)

    def clickhouse_database_list(
        self,
        project: str,
        service: str,
    ) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "clickhouse",
            "db",
        )
        return self.verify(self.get, path, result_key="databases")
