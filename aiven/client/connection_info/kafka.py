# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from ._utils import find_component, find_user
from .common import ConnectionInfoError, Store
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


@dataclass
class KafkaConnectionInfo:  # pylint: disable=too-few-public-methods
    host: str
    port: int

    def _kafkacat(
        self, protocol: str, ca_path: str, extra: Sequence[str], store: Store, get_project_ca: Callable[[], str]
    ) -> Sequence[str]:
        store.handle(get_project_ca, ca_path)
        address = f"{self.host}:{self.port}"
        return ["kafkacat", "-b", address, "-X", f"security.protocol={protocol}", "-X", f"ssl.ca.location={ca_path}", *extra]


@dataclass
class KafkaCertificateConnectionInfo(KafkaConnectionInfo):
    client_cert: str
    client_key: str

    def kafkacat(
        self, store: Store, get_project_ca: Callable[[], str], ca_path: str, client_key_path: str, client_cert_path: str
    ) -> Sequence[str]:
        store.handle(lambda: self.client_cert, client_cert_path)
        store.handle(lambda: self.client_key, client_key_path)

        extra = [
            "-X",
            f"ssl.key.location={client_key_path}",
            "-X",
            f"ssl.certificate.location={client_cert_path}",
        ]
        return self._kafkacat("SSL", ca_path, extra, store, get_project_ca)

    @classmethod
    def from_service(
        cls,
        service: Mapping[str, Any],
        *,
        route: str,
        privatelink_connection_id: str,
        username: str,
    ) -> KafkaCertificateConnectionInfo:
        if service["service_type"] != "kafka":
            raise ConnectionInfoError(
                "Cannot format kafka connection info for service type {service_type}".format_map(service)
            )

        info = find_component(
            service["components"],
            route=route,
            privatelink_connection_id=privatelink_connection_id,
            kafka_authentication_method="certificate",
        )
        user = find_user(service, username)
        if "access_cert" not in user:
            raise ConnectionInfoError(f"Could not find client certificate for username {username}")
        if "access_key" not in user:
            raise ConnectionInfoError(f"Could not find client key for username {username}")

        client_cert = user["access_cert"]
        client_key = user["access_key"]
        return cls(host=info["host"], port=info["port"], client_cert=client_cert, client_key=client_key)


@dataclass
class KafkaSASLConnectionInfo(KafkaConnectionInfo):
    username: str
    password: str

    @classmethod
    def from_service(
        cls,
        service: Mapping[str, Any],
        *,
        route: str,
        privatelink_connection_id: str,
        username: str,
    ) -> KafkaSASLConnectionInfo:
        if service["service_type"] != "kafka":
            raise ConnectionInfoError(
                "Cannot format kafka connection info for service type {service_type}".format_map(service)
            )

        info = find_component(
            service["components"],
            route=route,
            privatelink_connection_id=privatelink_connection_id,
            kafka_authentication_method="sasl",
        )
        user = find_user(service, username)
        if "password" not in user:
            raise ConnectionInfoError(f"Could not find password for username {username}")
        return cls(host=info["host"], port=info["port"], username=username, password=user["password"])

    def kafkacat(self, store: Store, get_project_ca: Callable[[], str], ca_path: str) -> Sequence[str]:
        extra = [
            "-X",
            "sasl.mechanisms=SCRAM-SHA-256",
            "-X",
            f"sasl.username={self.username}",
            "-X",
            f"sasl.password={self.password}",
        ]
        return self._kafkacat("SASL_SSL", ca_path, extra, store, get_project_ca)
