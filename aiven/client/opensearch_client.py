# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Mapping


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


class AivenOpenSearchClient(AivenOpenSearchSecurityClient):
    pass
