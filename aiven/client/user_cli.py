# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client import base_client, envdefault
from aiven.client.base_cli import AivenBaseCLI, no_auth
from aiven.client.cliarg import arg
from http import HTTPStatus
from typing import IO

import errno
import getpass
import json as jsonlib
import os


class AivenUserCLI(AivenBaseCLI):
    @no_auth
    @arg("email", nargs="?", help="User email address")
    @arg("--tenant", help="Login under a different tenant")
    @arg("--token", action="store_true", help="Provide an access token instead of password")
    def user__login(self) -> None:
        """Login as a user"""
        email = self.args.email
        if not email:
            email = input("Username (email): ")

        if self.args.token:
            token = self.enter_password(f"{email}'s Aiven access token: ", var="AIVEN_AUTH_TOKEN")
        else:
            password = self.enter_password(f"{email}'s Aiven password: ", var="AIVEN_PASSWORD")
            try:
                result = self.client.authenticate_user(email=email, password=password, tenant_id=self.args.tenant)
            except base_client.Error as ex:
                if ex.status == HTTPStatus.NOT_EXTENDED:
                    # Two-factor auth OTP required
                    otp = input("Two-factor authentication OTP: ")
                    result = self.client.authenticate_user(email=email, password=password, otp=otp)
                else:
                    raise
            token = result["token"]

        self._write_auth_token_file(token=token, email=email)

        # ensure that there is a working default project
        auth_token = self._get_auth_token()
        if auth_token:
            self.client.set_auth_token(auth_token)

        project = self.get_project(raise_if_none=False)
        projects = self.client.get_projects()
        if project and any(p["project_name"] == project for p in projects):
            # default project exists
            return

        if projects:
            default_project = projects[0]["project_name"]
            self.config["default_project"] = default_project
            self.config.save()
            self.log.info(
                "Default project set as '%s' (change with 'avn project switch <project>')",
                default_project,
            )
        else:
            self.log.info("No projects exists. You should probably create one with 'avn project create <name>'")

    @arg("--no-token-revoke", action="store_true", help="Do not revoke token")
    def user__logout(self) -> None:
        """Logout from current session"""
        if not self.args.no_token_revoke:
            auth_token = self._get_auth_token()
            if auth_token:
                self.client.access_token_revoke(token_prefix=auth_token)
        self._remove_auth_token_file()

    @arg.verbose
    def user__tokens_expire(self) -> None:
        """Expire all authorization tokens"""
        message = self.client.expire_user_tokens()["message"]
        print(message)

    @arg.verbose
    def user__password_change(self) -> None:
        """Change the password of the currently logged in user"""
        current_password = getpass.getpass("Current password: ")
        new_password = self.enter_password("New password: ", confirm=True)
        self.client.change_user_password(current_password, new_password)
        print("Password changed. Next, use 'avn user login' to log in again using your new password.")

    @arg("--description", required=True, help="Description of how the token will be used")
    @arg("--max-age-seconds", type=int, help="Maximum age of the token, if any")
    @arg(
        "--extend-when-used",
        action="store_true",
        help="Extend token's expiry time when used (only applicable if token is set to expire)",
    )
    @arg.json
    def user__access_token__create(self) -> None:
        """Creates new access token"""
        token_info = self.client.access_token_create(
            description=self.args.description,
            extend_when_used=self.args.extend_when_used,
            max_age_seconds=self.args.max_age_seconds,
        )
        layout = [
            "expiry_time",
            "description",
            "max_age_seconds",
            "extend_when_used",
            "full_token",
        ]
        self.print_response([token_info], json=self.args.json, table_layout=layout)

    @arg(
        "token_prefix",
        help="The full token or token prefix identifying the token to update",
    )
    @arg("--description", required=True, help="Description of how the token will be used")
    @arg.json
    def user__access_token__update(self) -> None:
        """Updates an existing access token"""
        token_info = self.client.access_token_update(token_prefix=self.args.token_prefix, description=self.args.description)
        layout = [
            "expiry_time",
            "token_prefix",
            "description",
            "max_age_seconds",
            "extend_when_used",
            "last_used_time",
            "last_ip",
            "last_user_agent",
        ]
        self.print_response([token_info], json=self.args.json, table_layout=layout)

    @arg(
        "token_prefix",
        help="The full token or token prefix identifying the token to revoke",
    )
    def user__access_token__revoke(self) -> None:
        """Revokes an access token"""
        self.client.access_token_revoke(token_prefix=self.args.token_prefix)
        print("Revoked")

    @arg.json
    def user__access_token__list(self) -> None:
        """List all of your access tokens"""
        tokens = self.client.access_tokens_list()
        layout = [
            "expiry_time",
            "token_prefix",
            "description",
            "max_age_seconds",
            "extend_when_used",
            "last_used_time",
            "last_ip",
            "last_user_agent",
        ]
        self.print_response(tokens, json=self.args.json, table_layout=layout)

    @arg.email
    @arg("--real-name", help="User real name", required=True)
    def user__create(self) -> None:
        """Create a user"""
        password = self.enter_password(
            "New aiven.io password for {}: ".format(self.args.email),
            var="AIVEN_NEW_PASSWORD",
            confirm=True,
        )
        result = self.client.create_user(email=self.args.email, password=password, real_name=self.args.real_name)

        self._write_auth_token_file(token=result["token"], email=self.args.email)

    @arg.json
    def user__info(self) -> None:
        """Show current user info"""
        result = self.client.get_user_info()
        layout = [["user", "real_name", "state", "token_validity_begin", "projects", "auth"]]
        self.print_response([result], json=self.args.json, table_layout=layout)

    def _write_auth_token_file(self, token: str, email: str) -> None:
        with self._open_auth_token_file(mode="w") as fp:
            fp.write(jsonlib.dumps({"auth_token": token, "user_email": email}))
            aiven_credentials_filename = fp.name
        os.chmod(aiven_credentials_filename, 0o600)
        self.log.info("Aiven credentials written to: %s", aiven_credentials_filename)

    def _open_auth_token_file(self, mode: str = "r") -> IO:
        auth_token_file_path = self._get_auth_token_file_name()
        try:
            return open(auth_token_file_path, mode, encoding="utf-8")
        except OSError as ex:
            if ex.errno == errno.ENOENT and mode == "w":
                aiven_dir = os.path.dirname(auth_token_file_path)
                os.makedirs(aiven_dir)
                os.chmod(aiven_dir, 0o700)
                return open(auth_token_file_path, mode, encoding="utf-8")
            raise

    def _remove_auth_token_file(self) -> None:
        try:
            os.unlink(self._get_auth_token_file_name())
        except OSError:
            pass

    def _get_auth_token_file_name(self) -> str:
        default_token_file_path = os.path.join(envdefault.AIVEN_CONFIG_DIR, "aiven-credentials.json")
        return os.environ.get("AIVEN_CREDENTIALS_FILE") or default_token_file_path

    def _get_auth_token(self) -> str | None:
        token = self.args.auth_token
        if token:
            return token

        try:
            with self._open_auth_token_file() as fp:
                return jsonlib.load(fp)["auth_token"]
        except OSError as ex:
            if ex.errno == errno.ENOENT:
                return None
            raise
