# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Any, Mapping, Sequence, TYPE_CHECKING

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass

UNCHANGED = object()  # used as a sentinel value


class AivenPrivateLinkClient(AivenClientBase):
    def _privatelink_path(self, project: str, service: str, cloud_provider: str, *rest: str) -> str:
        return self.build_path("project", project, "service", service, "privatelink", cloud_provider, *rest)

    def create_service_privatelink_aws(self, project: str, service: str, principals: Sequence[str]) -> Mapping:
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.post, path, body={"principals": principals})

    def update_service_privatelink_aws(self, project: str, service: str, principals: Sequence[str]) -> Mapping:
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.put, path, body={"principals": principals})

    def delete_service_privatelink_aws(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.delete, path)

    def get_service_privatelink_aws(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.get, path)

    def refresh_service_privatelink_aws(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "aws", "refresh")
        return self.verify(self.post, path)

    def list_service_privatelink_aws_connections(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self._privatelink_path(project, service, "aws") + "/connections"
        return self.verify(self.get, path, result_key="connections")

    def create_service_privatelink_azure(self, project: str, service: str, user_subscription_ids: Sequence[str]) -> Mapping:
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.post, path, body={"user_subscription_ids": user_subscription_ids})

    def refresh_service_privatelink_azure(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "azure", "refresh")
        return self.verify(self.post, path)

    def update_service_privatelink_azure(self, project: str, service: str, user_subscription_ids: Sequence[str]) -> Mapping:
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.put, path, body={"user_subscription_ids": user_subscription_ids})

    def update_service_privatelink_connection_azure(
        self, project: str, service: str, privatelink_connection_id: str, user_ip_address: str
    ) -> Mapping:
        path = self._privatelink_path(project, service, "azure", "connections", privatelink_connection_id)
        return self.verify(self.put, path, body={"user_ip_address": user_ip_address})

    def approve_service_privatelink_connection_azure(
        self, project: str, service: str, privatelink_connection_id: str
    ) -> Mapping:
        path = self._privatelink_path(project, service, "azure", "connections", privatelink_connection_id, "approve")
        return self.verify(self.post, path)

    def delete_service_privatelink_azure(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.delete, path)

    def get_service_privatelink_azure(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.get, path)

    def list_service_privatelink_azure_connections(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self._privatelink_path(project, service, "azure") + "/connections"
        return self.verify(self.get, path, result_key="connections")

    def create_service_privatelink_google(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "google")
        return self.verify(self.post, path, body={})

    def get_service_privatelink_google(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "google")
        return self.verify(self.get, path)

    def delete_service_privatelink_google(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "google")
        return self.verify(self.delete, path)

    def refresh_service_privatelink_google(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "google", "refresh")
        return self.verify(self.post, path)

    def list_service_privatelink_google_connections(self, project: str, service: str) -> Mapping:
        path = self._privatelink_path(project, service, "google", "connections")
        return self.verify(self.get, path)

    def approve_service_privatelink_google_connection(
        self, project: str, service: str, privatelink_connection_id: str, user_ip_address: str
    ) -> Mapping:
        path = self._privatelink_path(project, service, "google", "connections", privatelink_connection_id, "approve")
        return self.verify(self.post, path, body={"user_ip_address": user_ip_address})

    def list_privatelink_cloud_availability(self, project: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "privatelink-availability")
        return self.verify(self.get, path, result_key="privatelink_availability")
