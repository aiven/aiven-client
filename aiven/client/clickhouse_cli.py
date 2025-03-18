# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from . import argx
from aiven.client.base_cli import AivenBaseCLI
from aiven.client.cliarg import arg


class AivenClickhouseCLI(AivenBaseCLI):
    @arg.project
    @arg.service_name
    @arg.json
    @arg("database", help="Database name")
    def service__clickhouse__database__create(self) -> None:
        """Create a ClickHouse database"""
        project_name = self.get_project()
        response = self.client.clickhouse_database_create(
            project=project_name,
            service=self.args.service_name,
            database=self.args.database,
        )
        self.print_response(response)

    @arg.project
    @arg.service_name
    @arg.json
    @arg("database", help="Database name")
    def service__clickhouse__database__delete(self) -> None:
        """Delete a ClickHouse database"""
        project_name = self.get_project()
        response = self.client.clickhouse_database_delete(
            project=project_name,
            service=self.args.service_name,
            database=self.args.database,
        )
        self.print_response(response)

    @arg.project
    @arg.service_name
    @arg.json
    def service__clickhouse__database__list(self) -> None:
        """List ClickHouse databases"""
        project_name = self.get_project()
        layout = [
            [
                "name",
                "engine",
                "state",
            ]
        ]
        self.print_response(
            self.client.clickhouse_database_list(project=project_name, service=self.args.service_name),
            json=self.args.json,
            table_layout=layout,
        )

    @arg.project
    @arg.service_name
    @arg.json
    @arg("database", help="Database name")
    def service__clickhouse__table__list(self) -> None:
        """List ClickHouse database tables"""
        project_name = self.get_project()
        layout = [
            [
                "name",
                "uuid",
                "engine",
                "total_rows",
                "total_bytes",
                "state",
            ]
        ]
        databases = self.client.clickhouse_database_list(project=project_name, service=self.args.service_name)
        for database in databases:
            if database["name"] == self.args.database:
                self.print_response(database["tables"], json=self.args.json, table_layout=layout)
                return
        raise argx.UserError(f"Could not find database named {self.args.database}.")
