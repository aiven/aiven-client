# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Any, TYPE_CHECKING

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass


class AivenSustainabilityClient(AivenClientBase):
    def sustainability_service_plan_emissions_project(
        self, project: str, service_type: str, plan: str, cloud: str
    ) -> dict[str, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "sustainability",
                "emissions-project",
                "service-types",
                service_type,
                "plans",
                plan,
                "clouds",
                cloud,
            ),
        )

    def sustainability_project_emissions_estimate(self, project: str, since: str, until: str) -> dict[str, Any]:
        params = {"since": since, "until": until}
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "sustainability",
                "emissions",
            ),
            params=params,
        )
