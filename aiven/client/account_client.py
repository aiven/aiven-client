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


class AivenAccountOrganisationClient(AivenClientBase):
    def create_account(self, account_name: str) -> Mapping:
        body = {
            "account_name": account_name,
        }
        return self.verify(self.post, "/account", body=body, result_key="account")

    def delete_account(self, account_id: str) -> Mapping:
        return self.verify(self.delete, self.build_path("account", account_id))

    def update_account(self, account_id: str, account_name: str) -> Mapping:
        body = {
            "account_name": account_name,
        }
        return self.verify(
            self.put,
            self.build_path("account", account_id),
            body=body,
            result_key="account",
        )

    def get_accounts(self) -> Mapping:
        return self.verify(self.get, "/account", result_key="accounts")

    def list_teams(self, account_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "teams"),
            result_key="teams",
        )

    def create_team(self, account_id: str, team_name: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("account", account_id, "teams"),
            body={"team_name": team_name},
        )

    def delete_team(self, account_id: str, team_id: str) -> Mapping:
        return self.verify(self.delete, self.build_path("account", account_id, "team", team_id))

    def list_team_members(self, account_id: str, team_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "members"),
            result_key="members",
        )

    def add_team_member(self, account_id: str, team_id: str, email: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("account", account_id, "team", team_id, "members"),
            body={"email": email},
        )

    def list_team_invites(self, account_id: str, team_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "invites"),
            result_key="account_invites",
        )

    def delete_team_invite(self, account_id: str, team_id: str, email: str) -> Mapping:
        return self.verify(self.delete, self.build_path("account", account_id, "team", team_id, "invites", email))

    def delete_team_member(self, account_id: str, team_id: str, user_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "team", team_id, "member", user_id),
        )

    def list_team_projects(self, account_id: str, team_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "projects"),
            result_key="projects",
        )

    def attach_team_to_project(self, account_id: str, team_id: str, project: str, team_type: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("account", account_id, "team", team_id, "project", project),
            body={"team_type": team_type},
        )

    def create_oauth2_client(self, account_id: str, name: str, description: str | None = None) -> dict:
        return self.verify(
            self.post,
            self.build_path("account", account_id, "oauth_client"),
            body={"name": name, "description": description},
        )

    def list_oauth2_clients(self, account_id: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "oauth_client"),
            result_key="oauth2_clients",
        )

    def update_oauth2_client(
        self, account_id: str, client_id: str, name: str | None, description: str | None = None
    ) -> dict:
        return self.verify(
            self.patch,
            self.build_path("account", account_id, "oauth_client", client_id),
            body={"name": name, "description": description},
        )

    def get_oauth2_client(self, account_id: str, client_id: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "oauth_client", client_id),
        )

    def delete_oauth2_client(self, account_id: str, client_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "oauth_client", client_id),
        )

    def list_oauth2_client_redirects(self, account_id: str, client_id: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "oauth_client", client_id, "redirect"),
            result_key="redirects",
        )

    def create_oauth2_client_redirect(self, account_id: str, client_id: str, uri: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("account", account_id, "oauth_client", client_id, "redirect"),
            body={"redirect_uri": uri},
        )

    def delete_oauth2_client_redirect(self, account_id: str, client_id: str, redirect_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "oauth_client", client_id, "redirect", redirect_id),
        )

    def list_oauth2_client_secrets(self, account_id: str, client_id: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("account", account_id, "oauth_client", client_id, "secret"),
            result_key="secrets",
        )

    def create_oauth2_client_secret(self, account_id: str, client_id: str) -> Mapping:
        return self.verify(self.post, self.build_path("account", account_id, "oauth_client", client_id, "secret"), body={})

    def delete_oauth2_client_secret(self, account_id: str, client_id: str, secret_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "oauth_client", client_id, "secret", secret_id),
        )

    def detach_team_from_project(self, account_id: str, team_id: str, project: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "team", team_id, "project", project),
        )

    def get_organization(self, organization_id: str) -> dict[str, Any]:
        return self.verify(self.get, self.build_path("organization", organization_id))

    def get_organizations(self) -> Sequence:
        return self.verify(self.get, "/organizations", result_key="organizations")

    def delete_organization(self, organization_id: str) -> None:
        organization = self.verify(self.get, self.build_path("organization", organization_id))
        self.delete_account(account_id=organization["account_id"])

    def update_organization(self, organization_id: str, organization_name: str) -> dict[str, Any]:
        organization = self.verify(self.get, self.build_path("organization", organization_id))
        self.update_account(account_id=organization["account_id"], account_name=organization_name)
        return self.verify(self.get, self.build_path("organization", organization_id))

    def list_organization_users(self, organization_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("organization", organization_id, "user"),
            result_key="users",
        )

    def invite_organization_user(self, organization_id: str, email: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("organization", organization_id, "invitation"),
            body={"user_email": email},
        )

    def list_user_groups(self, organization_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get, self.build_path("organization", organization_id, "user-groups"), result_key="user_groups"
        )

    def get_user_group(self, organization_id: str, group_id: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("organization", organization_id, "user-groups", group_id, "members"),
            result_key="members",
        )

    def create_user_group(self, organization_id: str, group_name: str, props: dict[str, Any]) -> dict[str, Any]:
        props["user_group_name"] = group_name
        return self.verify(
            self.post,
            self.build_path("organization", organization_id, "user-groups"),
            body={k: v for (k, v) in props.items() if v is not None},
        )

    def update_user_group(self, organization_id: str, group_id: str, props: dict[str, Any]) -> dict[str, Any]:
        return self.verify(
            self.patch,
            self.build_path("organization", organization_id, "user-groups", group_id),
            body={k: v for (k, v) in props.items() if v is not None},
        )

    def delete_user_group(self, organization_id: str, group_id: str) -> None:
        self.verify(
            self.delete,
            self.build_path("organization", organization_id, "user-groups", group_id),
        )

    def create_payment_method_setup_intent(self) -> str:
        return self.verify(self.get, self.build_path("create_payment_method_setup_intent"), result_key="client_secret")

    def list_payment_methods(self, organization_id: str) -> Sequence[dict[str, Any]]:
        organization = self.verify(self.get, self.build_path("organization", organization_id))
        return self.verify(
            self.get, self.build_path("account", organization["account_id"], "payment_methods"), result_key="cards"
        )

    def attach_payment_method(self, organization_id: str, payment_method_id: str) -> dict[str, Any]:
        organization = self.verify(self.get, self.build_path("organization", organization_id))
        request = {
            "payment_method_id": payment_method_id,
        }
        return self.verify(
            self.post,
            self.build_path("account", organization["account_id"], "payment_methods"),
            body=request,
            result_key="card",
        )

    def delete_organization_card(self, organization_id: str, card_id: str) -> None:
        organization = self.verify(self.get, self.build_path("organization", organization_id))
        self.verify(self.delete, self.build_path("account", organization["account_id"], "payment_method", card_id))
