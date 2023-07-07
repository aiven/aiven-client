# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from ._utils import find_component, find_user, format_uri
from .common import ConnectionInfoError
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass
class PGConnectionInfo:
    host: str
    port: int
    username: str
    dbname: str
    password: str
    sslmode: str

    @classmethod
    def from_service(
        cls,
        service: Mapping[str, Any],
        *,
        route: str,
        usage: str,
        privatelink_connection_id: object | str,
        username: str,
        dbname: str,
        sslmode: str,
    ) -> PGConnectionInfo:
        if service["service_type"] != "pg":
            raise ConnectionInfoError("Cannot format pg connection info for service type {service_type}".format_map(service))

        info = find_component(
            service["components"], route=route, usage=usage, privatelink_connection_id=privatelink_connection_id
        )
        host = info["host"]
        port = info["port"]
        user = find_user(service, username)
        password = user.get("password")
        if password is None:
            raise ConnectionInfoError(f"Could not find password for username {username}")
        return cls(host=host, port=port, username=username, dbname=dbname, password=password, sslmode=sslmode)

    def params(self) -> Mapping[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "dbname": self.dbname,
            "password": self.password,
            "sslmode": self.sslmode,
        }

    def uri(self) -> str:
        return format_uri(
            scheme="postgres",
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            path=f"/{self.dbname}",
            query={"sslmode": self.sslmode},
        )

    def connection_string(self) -> str:
        return f"host='{self.host}' port='{self.port}' user={self.username} dbname='{self.dbname}'"

    def psql(self) -> Sequence[str]:
        return ["psql", self.uri()]
