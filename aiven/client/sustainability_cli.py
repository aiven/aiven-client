# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_cli import AivenBaseCLI
from aiven.client.cliarg import arg
from typing import Optional, TypeVar

S = TypeVar("S", str, Optional[str])  # Must be exactly str or str | None


class AivenSustainabilityCLI(AivenBaseCLI):
    @arg.project
    @arg.cloud
    @arg.json
    @arg.service_type
    @arg("-p", "--plan", help="subscription plan of service")
    def sustainability__service_plan_emissions_project(self) -> None:
        """Estimate emissions for a service plan"""
        project = self.get_project()
        service_type = self._get_service_type()
        plan = self._get_plan()
        cloud = self.args.cloud

        estimate = self.client.sustainability_service_plan_emissions_project(
            project=project, service_type=service_type, plan=plan, cloud=cloud
        )
        records = [{"measurement": k, "value": v} for k, v in estimate["emissions"].items()]

        layout = ["measurement", "value"]

        self.print_response(records, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.json
    @arg("--since", help="Period begin datestamp in format YYYYMMDD", required=True)
    @arg("--until", help="Period begin datestamp in format YYYYMMDD", required=True)
    def sustainability__project_emissions_estimate(self) -> None:
        """Estimate emissions for a project"""
        project = self.get_project()
        since = self.args.since
        until = self.args.until

        estimate = self.client.sustainability_project_emissions_estimate(project=project, since=since, until=until)

        records = [{"measurement": k, "value": v} for k, v in estimate["emissions"].items()]

        layout = ["measurement", "value"]

        self.print_response(records, json=self.args.json, table_layout=layout)
