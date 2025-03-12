# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Any, Mapping


class AivenOpenSearchSecurityClient(AivenClientBase):
    def opensearch_security_get(
        self,
        project: str,
        service: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "security",
            ),
        )

    def opensearch_security_set(
        self,
        project: str,
        service: str,
        password: str,
    ) -> Mapping:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "security",
                "admin",
            ),
            body={"admin_password": password},
        )

    def opensearch_security_reset(
        self,
        project: str,
        service: str,
        old_password: str,
        new_password: str,
    ) -> Mapping:
        return self.verify(
            self.put,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "security",
                "admin",
            ),
            body={"admin_password": old_password, "new_password": new_password},
        )


class AivenOpenSearchCustomRepoClient(AivenClientBase):
    def opensearch_custom_repo_list(
        self,
        project: str,
        service: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
            ),
        )

    def opensearch_snapshot_in_progress(
        self,
        project: str,
        service: str,
        repository_name: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                "_status",
            ),
        )

    def opensearch_snapshot_list(
        self,
        project: str,
        service: str,
        repository_name: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                "_all",
            ),
        )

    def opensearch_snapshot_show(
        self,
        project: str,
        service: str,
        repository_name: str,
        snapshot_name: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                snapshot_name,
            ),
        )

    def opensearch_snapshot_status(
        self,
        project: str,
        service: str,
        repository_name: str,
        snapshot_name: str,
    ) -> Mapping:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                snapshot_name,
                "_status",
            ),
        )

    def opensearch_snapshot_create(
        self,
        project: str,
        service: str,
        repository_name: str,
        snapshot_name: str,
        body: Mapping[str, Any],
    ) -> Mapping:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                snapshot_name,
            ),
            body=body,
        )

    def opensearch_snapshot_delete(
        self,
        project: str,
        service: str,
        repository_name: str,
        snapshot_name: str,
    ) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "opensearch",
                "_snapshot",
                repository_name,
                snapshot_name,
            ),
        )


class AivenOpenSearchClient(AivenOpenSearchSecurityClient, AivenOpenSearchCustomRepoClient):
    pass
