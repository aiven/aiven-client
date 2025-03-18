# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_cli import AivenBaseCLI
from aiven.client.cliarg import arg
from typing import Optional, TypeVar

S = TypeVar("S", str, Optional[str])  # Must be exactly str or str | None


class AivenPrivateLinkCLI(AivenBaseCLI):
    _aws_privatelink_principal_help = "AWS IAM principals allowed to connect to the Privatelink VPC endpoint service"

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg("--principal", dest="principals", action="append", metavar="PRINCIPAL", help=_aws_privatelink_principal_help)
    def service__privatelink__aws__create(self) -> None:
        """Create PrivateLink for a service"""
        resp = self.client.create_service_privatelink_aws(
            project=self.get_project(), service=self.args.service_name, principals=self.args.principals
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg("--principal", dest="principals", action="append", metavar="PRINCIPAL", help=_aws_privatelink_principal_help)
    def service__privatelink__aws__update(self) -> None:
        """Update PrivateLink for a service"""
        resp = self.client.update_service_privatelink_aws(
            project=self.get_project(), service=self.args.service_name, principals=self.args.principals
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__aws__get(self) -> None:
        """Get PrivateLink information for a service"""
        resp = self.client.get_service_privatelink_aws(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__aws__delete(self) -> None:
        """Delete PrivateLink for a service"""
        resp = self.client.delete_service_privatelink_aws(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    def service__privatelink__aws__refresh(self) -> None:
        """Refresh AWS PrivateLink to discover new endpoints"""
        self.client.refresh_service_privatelink_aws(
            project=self.get_project(),
            service=self.args.service_name,
        )

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__aws__connection__list(self) -> None:
        """List PrivateLink connections for a service"""
        resp = self.client.list_service_privatelink_aws_connections(
            project=self.get_project(), service=self.args.service_name
        )
        self.print_response(resp, format=self.args.format, json=self.args.json)

    _azure_privatelink_user_subscription_ids_help = "Azure subscription IDs allowed to connect to the Privatelink service"

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg(
        "--user-subscription-id",
        dest="user_subscription_ids",
        action="append",
        metavar="SUBSCRIPTION_ID",
        help=_azure_privatelink_user_subscription_ids_help,
    )
    def service__privatelink__azure__create(self) -> None:
        """Create Azure PrivateLink for a service"""
        resp = self.client.create_service_privatelink_azure(
            project=self.get_project(),
            service=self.args.service_name,
            user_subscription_ids=self.args.user_subscription_ids or [],
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    def service__privatelink__azure__refresh(self) -> None:
        """Refresh Azure PrivateLink to discover new endpoints"""
        self.client.refresh_service_privatelink_azure(
            project=self.get_project(),
            service=self.args.service_name,
        )

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg(
        "--user-subscription-id",
        dest="user_subscription_ids",
        action="append",
        metavar="SUBSCRIPTION_ID",
        help=_azure_privatelink_user_subscription_ids_help,
    )
    def service__privatelink__azure__update(self) -> None:
        """Update Azure PrivateLink for a service"""
        resp = self.client.update_service_privatelink_azure(
            project=self.get_project(),
            service=self.args.service_name,
            user_subscription_ids=self.args.user_subscription_ids or [],
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__azure__get(self) -> None:
        """Get Azure PrivateLink information for a service"""
        resp = self.client.get_service_privatelink_azure(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__azure__delete(self) -> None:
        """Delete Azure PrivateLink for a service"""
        resp = self.client.delete_service_privatelink_azure(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg(
        "--endpoint-ip-address",
        metavar="IP_ADDRESS",
        help="(Private) IP address of Azure endpoint in user subscription",
    )
    @arg("privatelink_connection_id", help="Aiven privatelink connection ID")
    def service__privatelink__azure__connection__update(self) -> None:
        """Update Azure PrivateLink connection"""
        resp = self.client.update_service_privatelink_connection_azure(
            project=self.get_project(),
            service=self.args.service_name,
            privatelink_connection_id=self.args.privatelink_connection_id,
            user_ip_address=self.args.endpoint_ip_address,
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    @arg("privatelink_connection_id", help="Aiven privatelink connection ID")
    def service__privatelink__azure__connection__approve(self) -> None:
        """Approve an Azure PrivateLink connection in pending-user-approval state"""
        resp = self.client.approve_service_privatelink_connection_azure(
            project=self.get_project(),
            service=self.args.service_name,
            privatelink_connection_id=self.args.privatelink_connection_id,
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__azure__connection__list(self) -> None:
        """List Azure PrivateLink connections for a service"""
        resp = self.client.list_service_privatelink_azure_connections(
            project=self.get_project(), service=self.args.service_name
        )
        layout = ["privatelink_connection_id", "private_endpoint_id", "state", "user_ip_address"]
        self.print_response(resp, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__create(self) -> None:
        """Create a privatelink for a Google Cloud service"""
        resp = self.client.create_service_privatelink_google(
            project=self.get_project(),
            service=self.args.service_name,
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__get(self) -> None:
        """Get privatelink information for a Google Cloud service"""
        resp = self.client.get_service_privatelink_google(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__delete(self) -> None:
        """Delete privatelink from a Google Cloud service"""
        resp = self.client.delete_service_privatelink_google(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__refresh(self) -> None:
        """Refresh privatelink state of a service in Google Cloud, including connected/pending endpoints"""
        resp = self.client.refresh_service_privatelink_google(project=self.get_project(), service=self.args.service_name)
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__connection__list(self) -> None:
        """List privatelink connections for a Google Cloud service"""
        resp = self.client.list_service_privatelink_google_connections(
            project=self.get_project(), service=self.args.service_name
        )
        print(resp)
        layout = ["privatelink_connection_id", "psc_connection_id", "state", "user_ip_address"]
        self.print_response(resp["connections"], format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--privatelink-connection-id", help="The Aiven assigned ID of the privatelink connection to approve", required=True)
    @arg("--user-ip-address", help="IP address assigned to the connecting Private Service Connect endpoint", required=True)
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__google__connection__approve(self) -> None:
        """Approve a privatelink connection to a Google Cloud service"""
        resp = self.client.approve_service_privatelink_google_connection(
            project=self.get_project(),
            service=self.args.service_name,
            privatelink_connection_id=self.args.privatelink_connection_id,
            user_ip_address=self.args.user_ip_address,
        )
        self.print_response([resp], format=self.args.format, json=self.args.json)

    @arg.project
    @arg("--format", help="Format string for output")
    @arg.json
    def service__privatelink__availability(self) -> None:
        """List privatelink cloud availability and prices"""
        resp = self.client.list_privatelink_cloud_availability(project=self.get_project())
        self.print_response(resp, format=self.args.format, json=self.args.json)
