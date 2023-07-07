# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from ._utils import find_component, find_user, format_uri
from .common import ConnectionInfoError
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass
class RedisConnectionInfo:
    host: str
    port: int
    username: str
    password: str
    db: str

    @classmethod
    def from_service(
        cls,
        service: Mapping[str, Any],
        *,
        route: str,
        usage: str,
        privatelink_connection_id: object | str,
        username: str,
        db: str,
    ) -> RedisConnectionInfo:
        if service["service_type"] != "redis":
            raise ConnectionInfoError(
                "Cannot format redis connection info for service type {service_type}".format_map(service)
            )

        info = find_component(
            service["components"], route=route, usage=usage, privatelink_connection_id=privatelink_connection_id
        )
        host = info["host"]
        port = info["port"]
        if username == "default":
            password = service["connection_info"]["redis_password"]
        else:
            user = find_user(service, username)
            password = user.get("password")

        if password is None:
            raise ConnectionInfoError(f"Could not find password for username {username}")
        return cls(host=host, port=port, username=username, db=db, password=password)

    def params(self) -> Mapping[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "db": self.db,
            "password": self.password,
        }

    def uri(self) -> str:
        return format_uri(
            scheme="rediss",
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            path=f"/{self.db}" if self.db else "",
            query={},
        )
