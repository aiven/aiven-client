# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.


from __future__ import annotations

from . import argx
from aiven.client.base_cli import AivenBaseCLI, USER_GROUP_COLUMNS
from aiven.client.cliarg import arg

import requests


class AivenAccountOrganisationCLI(AivenBaseCLI):
    @arg.json
    @arg("-n", "--name", required=True, help="Name of the account to create")
    def account__create(self) -> None:
        """Create new account"""
        account = self.client.create_account(self.args.name)
        self.print_response(account, json=self.args.json, single_item=True)

    @arg.json
    @arg.account_id
    @arg("-n", "--name", required=True, help="New name for the account")
    def account__update(self) -> None:
        """Update an account"""
        account = self.client.update_account(self.args.account_id, self.args.name)
        self.print_response(account, json=self.args.json, single_item=True)

    @arg.account_id
    def account__delete(self) -> None:
        """Delete an account"""
        self.client.delete_account(self.args.account_id)
        print("Deleted")

    @arg.json
    def account__list(self) -> None:
        """Lists all current accounts"""
        accounts = self.client.get_accounts()
        self.print_response(accounts, json=self.args.json)

    @arg.json
    @arg.account_id
    def account__team__list(self) -> None:
        """List account teams"""
        self.print_response(self.client.list_teams(self.args.account_id), json=self.args.json)

    @arg.json
    @arg.account_id
    @arg.team_name
    def account__team__create(self) -> None:
        """Create a team within an account"""
        self.client.create_team(self.args.account_id, self.args.team_name)

    @arg.json
    @arg.account_id
    @arg.team_id
    def account__team__delete(self) -> None:
        """Delete a team"""
        self.client.delete_team(self.args.account_id, self.args.team_id)

    @arg.json
    @arg.account_id
    @arg.team_id
    def account__team__user_list(self) -> None:
        """List team members"""
        self.print_response(
            self.client.list_team_members(self.args.account_id, self.args.team_id),
            json=self.args.json,
        )

    @arg.json
    @arg.account_id
    @arg.team_id
    @arg.email
    def account__team__user_invite(self) -> None:
        """Invite user to join a team"""
        self.client.add_team_member(self.args.account_id, self.args.team_id, self.args.email)

    @arg.json
    @arg.account_id
    @arg.team_id
    def account__team__user_list_pending(self) -> None:
        """List pending invitations to a team"""
        self.print_response(
            self.client.list_team_invites(self.args.account_id, self.args.team_id),
            json=self.args.json,
        )

    @arg.json
    @arg.account_id
    @arg.team_id
    @arg.email
    def account__team__invite_delete(self) -> None:
        """Delete pending invite from a team"""
        self.client.delete_team_invite(self.args.account_id, self.args.team_id, self.args.email)

    @arg.json
    @arg.account_id
    @arg.team_id
    @arg.user_id
    def account__team__user_delete(self) -> None:
        """Delete user from a team"""
        self.client.delete_team_member(self.args.account_id, self.args.team_id, self.args.user_id)

    @arg.json
    @arg.account_id
    @arg.team_id
    def account__team__project_list(self) -> None:
        """List projects associated to a team"""
        self.print_response(
            self.client.list_team_projects(self.args.account_id, self.args.team_id),
            json=self.args.json,
        )

    @arg.json
    @arg.account_id
    @arg.team_id
    @arg.project
    @arg(
        "--team-type",
        required=True,
        choices=["admin", "developer", "operator", "read_only"],
        help="Team type (permission level)",
    )
    def account__team__project_attach(self) -> None:
        """Attach team to a project"""
        self.client.attach_team_to_project(
            self.args.account_id,
            self.args.team_id,
            self.args.project,
            self.args.team_type,
        )

    @arg.json
    @arg.account_id
    @arg.team_id
    @arg.project
    def account__team__project_detach(self) -> None:
        """Detach team from a project"""
        self.client.detach_team_from_project(self.args.account_id, self.args.team_id, self.args.project)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    def account__oauth2_client__get(self) -> None:
        """Get an OAuth2 client configuration."""

        oauth2_client = self.client.get_oauth2_client(self.args.account_id, self.args.oauth2_client_id)
        table_layout = ["client_id", "name", "description"]
        self.print_response(oauth2_client, json=self.args.json, single_item=True, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    @arg("-n", "--name", required=True, help="OAuth2 application name")
    @arg(
        "-d",
        "--description",
        required=False,
        help="App description",
    )
    def account__oauth2_client__update(self) -> None:
        """Get an OAuth2 client configuration."""

        oauth2_client = self.client.update_oauth2_client(
            account_id=self.args.account_id,
            client_id=self.args.oauth2_client_id,
            name=self.args.name,
            description=self.args.description,
        )
        table_layout = ["client_id", "name", "description"]
        self.print_response(oauth2_client, json=self.args.json, single_item=True, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    def account__oauth2_client__delete(self) -> None:
        """Remove an OAuth2 client."""

        self.client.delete_oauth2_client(self.args.account_id, self.args.oauth2_client_id)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    def account__oauth2_client__redirect_list(self) -> None:
        """List OAuth2 client redirects."""

        oauth2_client_redirects = self.client.list_oauth2_client_redirects(self.args.account_id, self.args.oauth2_client_id)
        table_layout = ["redirect_id", "redirect_uri"]
        self.print_response(oauth2_client_redirects, json=self.args.json, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    @arg("--redirect-uri", help="Redirect URI")
    def account__oauth2_client__redirect_create(self) -> None:
        """Add an allowed redirect URI to an OAuth2 client."""

        redirect = self.client.create_oauth2_client_redirect(
            self.args.account_id, self.args.oauth2_client_id, self.args.redirect_uri
        )

        table_layout = ["redirect_id", "redirect_uri"]
        self.print_response(redirect, json=self.args.json, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    @arg("--redirect-uri-id", help="Redirect URI id", required=True)
    def account__oauth2_client__redirect_delete(self) -> None:
        """Add an allowed redirect URI to an OAuth2 client."""

        self.client.delete_oauth2_client_redirect(
            self.args.account_id, self.args.oauth2_client_id, self.args.redirect_uri_id
        )

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    def account__oauth2_client__secret_list(self) -> None:
        """List OAuth2 client secrets."""

        oauth2_client_secrets = self.client.list_oauth2_client_secrets(self.args.account_id, self.args.oauth2_client_id)
        table_layout = ["secret_id", "secret_suffix"]
        self.print_response(oauth2_client_secrets, json=self.args.json, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    def account__oauth2_client__secret_create(self) -> None:
        """List OAuth2 client secrets."""

        secret = self.client.create_oauth2_client_secret(self.args.account_id, self.args.oauth2_client_id)
        table_layout = ["secret_id", "secret_suffix", "secret"]
        self.print_response(secret, json=self.args.json, single_item=True, table_layout=table_layout)

    @arg.json
    @arg.account_id
    @arg("--oauth2-client-id", help="OAuth2 client id", required=True)
    @arg("--secret-id", help="Client secret id")
    def account__oauth2_client__secret_delete(self) -> None:
        """List OAuth2 client secrets."""

        self.client.delete_oauth2_client_secret(self.args.account_id, self.args.oauth2_client_id, self.args.secret_id)

    @arg.json
    @arg("name", help="Name of the organization to create")
    @arg.force
    def organization__create(self) -> None:
        """Create new organization"""
        if not self.args.force:
            confirmation_result = self.confirm(
                "Settings like billing details and authentication methods \
    cannot be shared across multiple organizations.\
    \nWhen you create a new organization, you must configure each of these settings manually.\
    \n\nTo use your current settings, create an organizational unit within this organization instead.\
    \n\nI understand and want to create a new organization (y/N)? "
            )

            if not confirmation_result:
                raise argx.UserError("Aborted")

        organizations = self.client.create_account(self.args.name)
        layout = [
            "organization_id",
            "account_id",
            "create_time",
            "update_time",
        ]
        self.print_response(organizations, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    def organization__list(self) -> None:
        """Lists all current organizations"""
        organizations = self.client.get_organizations()
        layout = [
            "organization_name",
            "organization_id",
            "account_id",
            "create_time",
            "update_time",
            "tier",
        ]
        self.print_response(organizations, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id_positional
    @arg("-n", "--name", required=True, help="New name for the organization")
    def organization__update(self) -> None:
        """Update an organization"""
        layout = [
            "organization_name",
            "organization_id",
            "account_id",
            "create_time",
            "update_time",
        ]
        organization = self.client.update_organization(self.args.organization_id, self.args.name)
        self.print_response(organization, json=self.args.json, single_item=True, table_layout=layout)

    @arg.organization_id_positional
    @arg.force
    def organization__delete(self) -> None:
        """Delete an organization"""
        if not self.args.force:
            self.print_boxed(
                [
                    "Deleting organization cannot be undone and all data in the organization will be lost!",
                ]
            )

        if not self.confirm("Confirm delete (y/N)?"):
            raise argx.UserError("Aborted")

        self.client.delete_organization(self.args.organization_id)
        print("Deleted")

    @arg.json
    @arg.organization_id
    def organization__user__list(self) -> None:
        """Lists organization users"""
        users = self.client.list_organization_users(self.args.organization_id)
        layout = [
            "user_info.user_email",
            "user_info.real_name",
            "user_info.state",
            "last_activity_time",
        ]
        self.print_response(users, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg.email
    def organization__user__invite(self) -> None:
        """Invite user to join an organization"""
        self.client.invite_organization_user(self.args.organization_id, self.args.email)

    @arg.json
    @arg.organization_id
    def organization__group__list(self) -> None:
        """List user groups in an organization"""
        groups = self.client.list_user_groups(self.args.organization_id)
        layout = [
            "user_group_name",
            "user_group_id",
            "member_count",
            "description",
        ]
        self.print_response(groups, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg.group_id_positional
    def organization__group__show(self) -> None:
        """Show the user group details"""
        members = self.client.get_user_group(self.args.organization_id, self.args.group_id)
        layout = [
            "user_info.user_email",
            "user_info.real_name",
            "last_activity_time",
            "user_info.state",
        ]
        self.print_response(members, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg("name", help="Name of the organization user group to create")
    @arg("--description", help="Description for the organization user group")
    def organization__group__create(self) -> None:
        """Create a user group in an organization"""
        group = self.client.create_user_group(
            organization_id=self.args.organization_id,
            group_name=self.args.name,
            props={
                "description": self.args.description or "",
            },
        )
        self.print_response(group, json=self.args.json, table_layout=USER_GROUP_COLUMNS, single_item=True)

    @arg.json
    @arg.organization_id
    @arg.group_id_positional
    @arg("--name", help="Name for the organization user group")
    @arg("--description", help="Description for the organization user group")
    def organization__group__update(self) -> None:
        """Update properties of an organization user group"""
        group = self.client.update_user_group(
            organization_id=self.args.organization_id,
            group_id=self.args.group_id,
            props={
                "user_group_name": self.args.name,
                "description": self.args.description,
            },
        )
        self.print_response(group, json=self.args.json, table_layout=USER_GROUP_COLUMNS, single_item=True)

    @arg.force
    @arg.organization_id
    @arg.group_id_positional
    def organization__group__delete(self) -> None:
        """Delete organization user group"""
        if not self.args.force:
            self.print_boxed(
                [
                    "Deleting the user group cannot be undone and all data in the group will be lost!",
                ]
            )

        if not self.confirm("Confirm delete (y/N)?"):
            raise argx.UserError("Aborted")

        self.client.delete_user_group(self.args.organization_id, self.args.group_id)

    def _get_stripe_payment_method_id(self, name: str, number: str, exp_month: int, exp_year: int, cvc: str) -> str:
        """Obtains payment method identifier from Stripe"""
        stripe_key = self.client.get_stripe_key()
        raw_client_secret = self.client.create_payment_method_setup_intent()

        request_payload = {
            "client_secret": raw_client_secret,
            "payment_method_data[billing_details][name]": name,
            "payment_method_data[card][number]": number,
            "payment_method_data[card][cvc]": cvc,
            "payment_method_data[card][exp_month]": exp_month,
            "payment_method_data[card][exp_year]": exp_year,
            "payment_method_data[type]": "card",
        }

        client_secret_url_part = "_".join(raw_client_secret.split("_")[:2])
        response = requests.post(
            f"https://api.stripe.com/v1/setup_intents/{client_secret_url_part}/confirm",
            data=request_payload,
            auth=(stripe_key, ""),
            timeout=30,
        )

        if not response.ok:
            response.raise_for_status()
        return response.json()["payment_method"]

    @arg.json
    @arg.organization_id
    def organization__card__list(self) -> None:
        """List organization cards"""
        cards = self.client.list_payment_methods(self.args.organization_id)
        for card in cards:
            card["expiration"] = f"{card['exp_month']:02d}/{card['exp_year']}"
            card["number"] = f"**** **** **** {card['last4']}"

        layout = [
            "card_id",
            "name",
            "number",
            "expiration",
        ]
        self.print_response(cards, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg("--cvc", help="Credit card security code", required=True)
    @arg("--exp-month", help="Card expiration month (1-12)", type=int, required=True)
    @arg("--exp-year", help="Card expiration year", type=int, required=True)
    @arg("--name", help="Name on card", required=True)
    @arg("--number", help="Credit card number", type=int, required=True)
    def organization__card__create(self) -> None:
        """Add a credit card"""

        payment_method_id = self._get_stripe_payment_method_id(
            self.args.name,
            self.args.number,
            self.args.exp_month,
            self.args.exp_year,
            self.args.cvc,
        )
        card = self.client.attach_payment_method(self.args.organization_id, payment_method_id)

        card["expiration"] = f"{card['exp_month']:02d}/{card['exp_year']}"
        card["number"] = f"**** **** **** {card['last4']}"
        layout = [
            "card_id",
            "name",
            "number",
            "expiration",
        ]
        self.print_response(card, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.force
    @arg.organization_id
    @arg("card_id", help="Credit card identifier")
    def organization__card__delete(self) -> None:
        """Delete organization card"""
        if not self.confirm("Confirm delete (y/N)?"):
            raise argx.UserError("Aborted")
        self.client.delete_organization_card(self.args.organization_id, self.args.card_id)
        print("Deleted")
