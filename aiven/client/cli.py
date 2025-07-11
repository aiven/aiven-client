# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from . import argx, client, units
from aiven.client import AivenClient, envdefault
from aiven.client.cliarg import arg
from aiven.client.client import Tag
from aiven.client.common import UNDEFINED
from aiven.client.connection_info.common import Store
from aiven.client.connection_info.kafka import KafkaCertificateConnectionInfo, KafkaSASLConnectionInfo
from aiven.client.connection_info.pg import PGConnectionInfo
from aiven.client.connection_info.redis import RedisConnectionInfo
from aiven.client.speller import suggest
from argparse import ArgumentParser
from ast import literal_eval
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http import HTTPStatus
from typing import Any, Callable, Final, IO, Mapping, Optional, Protocol, Sequence, TypeVar
from urllib.parse import urlparse

import errno
import getpass
import json as jsonlib
import os
import re
import requests
import subprocess
import sys
import time

S = TypeVar("S", str, Optional[str])  # Must be exactly str or str | None

USER_GROUP_COLUMNS = [
    "user_group_name",
    "user_group_id",
    "description",
]
EOL_ADVANCE_WARNING_TIME = timedelta(weeks=26)  # Give 6 months advance notice for EOL services

REDIS_VALKEY_ACL_ARGS = [
    "redis_acl_keys",
    "redis_acl_commands",
    "redis_acl_categories",
    "redis_acl_channels",
    "valkey_acl_keys",
    "valkey_acl_commands",
    "valkey_acl_categories",
    "valkey_acl_channels",
]


def convert_str_to_value(schema: Mapping[str, Any], value: Any | None) -> Any:
    if value is not None:
        if "string" in schema["type"] or "object" in schema["type"]:
            return value
        elif "integer" in schema["type"]:
            return int(value, 0)  # automatically convert from '123', '0x123', '0o644', etc.
        elif "number" in schema["type"]:
            return float(value)
        elif "boolean" in schema["type"]:
            values = {
                "1": True,
                "0": False,
                "true": True,
                "false": False,
            }
            try:
                return values[value]
            except KeyError as ex:
                raise argx.UserError(
                    "Invalid boolean value {!r}: expected one of {}".format(value, ", ".join(values))
                ) from ex
        elif "array" in schema["type"]:
            evaluated_array = literal_eval(value)
            values_array = []
            for item in evaluated_array:
                values_array.append(convert_str_to_value(schema["items"], item))
            return values_array
        else:
            raise argx.UserError("Support for option value type(s) {!r} not implemented".format(schema["type"]))

    if "null" in schema["type"]:
        return None

    raise argx.UserError("Support for option value type(s) {!r} not implemented".format(schema["type"]))


tag_key_re = re.compile(r"[\w\-]+")
tag_value_re = re.compile(r"[\w\-,. ]*")


def parse_tag_str(kv: str) -> Tag:
    k, v = (kv.split(sep="=", maxsplit=1) + [""])[:2]

    if not tag_key_re.fullmatch(k):
        raise argx.UserError(f"Tag key '{k}' must consist of alpha-numeric characters, underscores or dashes")

    if not tag_value_re.fullmatch(v):
        raise argx.UserError(
            f"Tag value '{k}={v}' must consist of alpha-numeric characters, underscores, dashes, commas or dots"
        )

    return {"key": k, "value": v}


def parse_untag_str(k: str) -> str:
    if not tag_key_re.match(k):
        raise argx.UserError(f"Tag key {k} must consist of alpha-numeric characters, underscores or dashes")

    return k


def no_auth(fun: Callable) -> Callable:
    fun.no_auth = True  # type: ignore
    return fun


def optional_auth(fun: Callable) -> Callable:
    fun.optional_auth = True  # type: ignore
    return fun


def is_truthy(value: str) -> bool:
    return value.lower() in {"y", "yes", "t", "true", "1", "ok"}


def parse_iso8601(value: str) -> datetime:
    # Python 3.6 doesn't support fromisoformat()
    # or 'Z' as valid for '%z' format string
    if value[-1] == "Z":
        value = value[:-1] + "+0000"

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")


def get_current_date() -> datetime:
    return datetime.now(timezone.utc)


class ClientFactory(Protocol):
    def __call__(self, base_url: str, show_http: bool, request_timeout: int | None) -> client.AivenClient:
        ...


class AivenCLI(argx.CommandLineTool):
    client: AivenClient

    def __init__(self, client_factory: ClientFactory = AivenClient):
        argx.CommandLineTool.__init__(self, "avn")
        self.client_factory = client_factory

    def add_args(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--auth-ca",
            help="CA certificate to use [AIVEN_CA_CERT], default %(default)r",
            default=envdefault.AIVEN_CA_CERT,
            metavar="FILE",
        )
        parser.add_argument(
            "--auth-token",
            help="Client auth token to use [AIVEN_AUTH_TOKEN], [AIVEN_CREDENTIALS_FILE]",
            default=envdefault.AIVEN_AUTH_TOKEN,
        )
        parser.add_argument("--show-http", help="Show HTTP requests and responses", action="store_true")
        parser.add_argument(
            "--url",
            help="Server base url default %(default)r",
            default=envdefault.AIVEN_WEB_URL,
        )
        parser.add_argument(
            "--request-timeout",
            type=int,
            default=None,
            help="Wait for up to N seconds for a response to a request (default: infinite)",
        )

    def collect_user_config_options(self, obj_def: Mapping[str, Any], prefixes: list[str] | None = None) -> dict[str, Any]:
        opts = {}
        for prop, spec in sorted(obj_def.get("properties", {}).items()):
            full_prop = prefixes + [prop] if prefixes else [prop]
            full_name = ".".join(full_prop)
            types = spec["type"]
            if not isinstance(types, list):
                types = [types]
            # "object" or ["object", "null"]
            if "object" in types:
                opts.update(self.collect_user_config_options(spec, prefixes=full_prop))
                if "null" in types:
                    # allow removing user config option
                    opts[full_name] = {
                        "property_parts": full_prop,
                        "title": "Remove {}".format(prop),
                        "type": "null",
                    }
            else:
                opts[full_name] = dict(spec, property_parts=full_prop)
        for spec in sorted(obj_def.get("patternProperties", {}).values()):
            full_prop = prefixes + ["KEY"] if prefixes else ["KEY"]
            full_name = ".".join(full_prop)
            if spec["type"] == "object":
                opts.update(self.collect_user_config_options(spec, prefixes=full_prop))
            else:
                title = ": ".join([obj_def["title"], spec["title"]]) if "title" in spec else obj_def["title"]
                opts[full_name] = dict(spec, property_parts=full_prop, title=title)
        return opts

    def create_user_config(self, user_config_schema: Mapping[str, Any]) -> dict[str, Any]:
        """Convert a list of ["foo.bar='baz'"] to {"foo": {"bar": "baz"}}"""
        user_option_remove = []
        if hasattr(self.args, "user_option_remove"):
            user_option_remove = self.args.user_option_remove
        if not self.args.user_config and not user_option_remove:
            return {}

        options = self.collect_user_config_options(user_config_schema)
        user_config: dict[str, Any] = {}
        for key_value in self.args.user_config:
            try:
                key, value = key_value.split("=", 1)
            except ValueError as ex:
                raise argx.UserError(
                    "Invalid config value: {!r}, expected '<KEY>[.<SUBKEY>]=<JSON_VALUE>'".format(key_value)
                ) from ex

            opt_schema = options.get(key)
            if not opt_schema:
                # Exact key not found, try generic one
                generic_key = ".".join(key.split(".")[:-1] + ["KEY"])
                opt_schema = options.get(generic_key)

            if not opt_schema:
                raise argx.UserError(
                    "Unsupported option {!r}, available options: {}".format(key, ", ".join(options) or "none")
                )

            try:
                value = convert_str_to_value(opt_schema, value)
            except ValueError as ex:
                raise argx.UserError("Invalid value {!r}: {}".format(key_value, ex))

            leaf_config, leaf_key = self.get_leaf_config_and_key(config=user_config, key=key, opt_schema=opt_schema)
            leaf_config[leaf_key] = value

        for opt in user_option_remove:
            opt_schema = options.get(opt)
            if not opt_schema:
                raise argx.UserError(
                    "Unsupported option {!r}, available options: {}".format(opt, ", ".join(options) or "none")
                )

            if "null" not in opt_schema["type"]:
                raise argx.UserError("Removing option {!r} is not supported".format(opt))

            leaf_config, leaf_key = self.get_leaf_config_and_key(config=user_config, key=opt, opt_schema=opt_schema)
            leaf_config[leaf_key] = None

        return user_config

    @classmethod
    def get_leaf_config_and_key(
        cls, *, config: dict[str, Any], key: str, opt_schema: Mapping[str, Any]
    ) -> tuple[dict[str, Any], str]:
        key_suffix = key
        for part in opt_schema["property_parts"][:-1]:
            prefix = "{}.".format(part)
            if not key_suffix.startswith(prefix):
                raise argx.UserError("Expected {} to start with {} (full key {})".format(key_suffix, prefix, key))
            key_suffix = key_suffix[len(prefix) :]
            config = config.setdefault(part, {})
        return config, key_suffix

    def enter_password(self, prompt: str, var: str = "AIVEN_PASSWORD", confirm: bool = False) -> str:
        """Prompt user for a password"""
        password = os.environ.get(var)
        if password:
            return password

        password = getpass.getpass(prompt)
        if confirm:
            again = getpass.getpass("Confirm password again: ")
            if password != again:
                raise argx.UserError("Passwords do not match")

        return password

    def print_boxed(self, lines: list[str]) -> None:
        longest = max(len(line) for line in lines)

        print("*" * longest)
        for line in lines:
            print(line)
        print("*" * longest)

    def confirm(self, prompt: str = "confirm (y/N)? ") -> bool:
        if self.args.force or is_truthy(os.environ.get("AIVEN_FORCE", "no")):
            return True

        answer = input(prompt)
        return is_truthy(answer)

    def get_project(self, raise_if_none: bool = True, fallback_to_default_project: bool = True) -> str:
        """Return project given as cmdline argument or the default project from config file"""
        if getattr(self.args, "project", None) and self.args.project:
            return self.args.project

        if fallback_to_default_project:
            default_project = self.config.get("default_project", "")
            if raise_if_none and not default_project:
                raise argx.UserError(
                    "Specify project: use --project in the command line or the default_project item in the config file."
                )
            return default_project
        elif raise_if_none:
            raise argx.UserError("A project is required. Use --project in the command line.")

        return ""

    @no_auth
    @arg("pattern", nargs="*", help="command search pattern")
    def help(self) -> None:
        """List commands"""
        output = []
        patterns = [re.compile(p, re.I) for p in self.args.pattern]
        for plugin in self._extensions:
            for prop_name in dir(plugin):
                if prop_name.startswith("_"):
                    continue
                prop = getattr(plugin, prop_name)
                arg_list = getattr(prop, argx.ARG_LIST_PROP, None)
                if arg_list is not None:
                    cmd = prop_name.replace("__", " ").replace("_", "-")
                    if patterns and not all((p.search(cmd) or p.search(prop.__doc__)) for p in patterns):
                        continue

                    output.append({"command": cmd, "help": " ".join(prop.__doc__.split())})

        layout = ["command", "help"]
        self.print_response(output, json=False, table_layout=layout)

    @no_auth
    @arg()
    def crab(self) -> None:
        """Aiven crab"""
        output = """
                `'+;`         `'+;`
              '@@@#@@@`     '@@@#@@@`
             #@.     #@.   @@.     #@.
             @: ,@@   @@   @: ,@@   @@
            ,@  @@@@@ :@  :@  @@@@@ .@
             @  #@@@. #@   @` #@@@` @@
             @@      `@#   @@      `@#
              @@#. :@@+     @@#. :@@#
               `+@@@'        `#@@@'
       ,;:`                             ,;;.
     @@@@@@#     .+@@@@@@@@@@@@@'.    `@@@@@@@
    @@@@@#    @@@@@@@@@@@@@@@@@@@@@@+    @@@@@@
     @@@   ;@@@@@@@@@@@@@@@@@@@@@@@@@@@`  `@@;
      `  `@@@@@@@@@@@        ;@@@@@@@@@@@
  `@@@  '@@@@@@@@@@@@@       @@@@@@@@@@@@@`  @@@
 '@@@` .@@@@@@@@@@@@@@@    `@@@@@@@@@@@@@@@  @@@@`
 @@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@
'@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@
,:::;  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ,:::
   :@  ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  #@
   @@@  +@#+#@@@@@@@@@@@@@@@@@@@@@@@@@#+#@.  @@@
   @@@@        '@@@@@@@@@@@@@@@@@@@.        @@@@
   @@@  @@@@@@+  @@@@@@@@@@@@@@@@@  @@@@@@;  @@@
   @@  @@@@@@@@@  @@@@@@@@@@@@@@@ `@@@@@@@@@  @+
      @@@@@@@@@@@ :@@@@@@@@@@@@@  @@@@@@@@@@@ '
     `@@@@@@@@@@@       ```      ,@@@@@@@@@@@
     `@@@@@@   '@                :@:   @@@@@@
      @@@@@:                           @@@@@@
       @@@@@                           @@@@@
        @@@@#                         @@@@'

        """
        print(output)

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
            except client.Error as ex:
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

    def _show_logs(self, msgs: Mapping[str, Any]) -> str:
        if self.args.json:
            print(jsonlib.dumps(msgs["logs"], indent=4, sort_keys=True))
        else:
            for log_msg in msgs["logs"]:
                print("{time:<27}{hostname} {unit} {msg}".format(**log_msg))
        return msgs["offset"]

    @arg.project
    @arg.service_name
    @arg.json
    @arg(
        "-S",
        "--sort-order",
        type=str,
        default="asc",
        choices=["desc", "asc"],
        help="Sort direction for log fetching",
    )
    @arg("-n", "--limit", type=int, default=100, help="Get up to N rows of logs")
    @arg("-f", "--follow", action="store_true", default=False)
    def service__logs(self) -> None:
        """View project logs"""
        previous_offset: str | None = None
        consecutive_errors_limit: Final = 10
        consecutive_errors = 0
        while True:
            try:
                msgs = self.client.get_service_logs(
                    project=self.get_project(),
                    limit=self.args.limit,
                    offset=previous_offset,
                    service=self.args.service_name,
                    sort_order=self.args.sort_order,
                )
            except requests.RequestException as ex:
                if not self.args.follow:
                    raise ex
                consecutive_errors += 1
                if consecutive_errors > consecutive_errors_limit:
                    raise argx.UserError("Fetching logs failed repeatedly, aborting.")
                sys.stderr.write("Fetching log messages failed with {}. Retrying after 10s\n".format(ex))
                time.sleep(10.0)
                continue
            consecutive_errors = 0
            new_offset = self._show_logs(msgs)
            if not msgs["logs"] and previous_offset is not None and self.args.sort_order == "desc":
                # Quit because since we didn't find older messages than this, we'll never find any.
                break
            if not self.args.follow:
                break
            if previous_offset == new_offset:
                # No new msgs, sleep for a while
                time.sleep(10.0)
            previous_offset = new_offset

    @arg.project
    @arg.json
    @arg("-n", "--limit", type=int, default=100, help="Get up to N rows of logs")
    def events(self) -> None:
        """View project event logs"""
        events = self.client.get_events(project=self.get_project(), limit=self.args.limit)

        if self.args.json:
            print(jsonlib.dumps(events, indent=4, sort_keys=True))
            return

        for msg in events:
            if not msg["service_name"]:
                msg["service_name"] = ""

        layout = ["time", "actor", "event_type", "service_name", "event_desc"]
        self.print_response(events, json=self.args.json, table_layout=layout)

    @optional_auth
    @arg.project
    @arg.json
    def cloud__list(self) -> None:
        """List cloud types"""
        project = self.get_project(raise_if_none=False)
        if project and not self.client.auth_token:
            raise argx.UserError("authentication is required to list clouds for a specific project")
        self.print_response(self.client.get_clouds(project=project), json=self.args.json)

    @staticmethod
    def describe_plan(plan: Mapping[str, Any], node_count: int, service_plan: str) -> str:
        """Describe a plan based on their specs as published in the api, returning strings like:
        "Basic-0 (4 CPU, 123 MB RAM) "
        "Basic-1 (4 CPU, 1 GB RAM, 9 GB disk) "
        "Dual-1 (4 CPU, 1 GB RAM, 9 GB disk) high availability pair"
        "Quad-2 (4 CPU, 2 GB RAM, 9 GB disk) 4-node high availability set"
        """
        if plan["node_memory_mb"] < units.MIB_IN_GIB:
            ram_amount = "{} MB".format(plan["node_memory_mb"])
        else:
            ram_amount = "{:.0f} GB".format(units.convert_mib_to_gib(plan["node_memory_mb"]))

        if plan["disk_space_mb"]:
            if plan.get("disk_space_cap_mb"):
                disk_desc = ", {:.0f}-{:.0f} GB disk".format(
                    units.convert_mib_to_gib(plan["disk_space_mb"]), units.convert_mib_to_gib(plan["disk_space_cap_mb"])
                )
            else:
                disk_desc = ", {:.0f} GB disk".format(units.convert_mib_to_gib(plan["disk_space_mb"]))
        else:
            disk_desc = ""

        if node_count == 2:  # noqa: PLR2004
            plan_qual = " high availability pair"
        elif node_count > 2:  # noqa: PLR2004
            plan_qual = " {}-node high availability set".format(node_count)
        else:
            plan_qual = ""

        return "{name} ({cpu_count} CPU, {ram_amount} RAM{disk_desc}){qual}".format(
            name=service_plan.title(),
            cpu_count=plan["node_cpu_count"],
            ram_amount=ram_amount,
            disk_desc=disk_desc,
            qual=plan_qual,
        )

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

    @staticmethod
    def _parse_auth_config_options(config_cmdline: Sequence[str], config_file: Sequence[str]) -> Mapping[str, str]:
        options = {}
        for name_and_value in config_cmdline:
            if "=" not in name_and_value:
                raise argx.UserError("Invalid custom value, missing '=': {}".format(name_and_value))
            name, value = name_and_value.split("=", 1)
            options[name] = value
        for name_and_value in config_file:
            if "=" not in name_and_value:
                raise argx.UserError("Invalid custom value, missing '=': {}".format(name_and_value))
            name, filename = name_and_value.split("=", 1)
            if not os.path.isfile(filename):
                raise argx.UserError("No such file {!r}".format(filename))
            with open(filename, encoding="utf-8") as fob:
                value = fob.read()
            options[name] = value
        return options

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

    @optional_auth
    @arg.project
    @arg.cloud
    @arg.json
    @arg.service_type
    @arg("--monthly", help="Show monthly price estimates", action="store_true")
    def service__plans(self) -> None:
        """List service plans"""
        project = self.get_project()
        if project and not self.client.auth_token:
            raise argx.UserError("authentication is required to list service plans for a specific project")
        if not self.args.cloud:
            print("Used cloud not defined, only showing service types!\n")

        service_types = self.client.get_service_types(project=project)
        if self.args.json:
            print(jsonlib.dumps(service_types, indent=4, sort_keys=True))
            return

        output = []
        for service_type, prop in service_types.items():
            if self.args.service_type and service_type != self.args.service_type:
                continue
            entry = prop.copy()
            entry["service_type"] = service_type
            output.append(entry)

        dformat = Decimal("0") if self.args.monthly else Decimal("0.000")
        for info in sorted(output, key=lambda s: s["description"]):
            print("{} Plans:\n".format(info["description"]))
            for plan in info["service_plans"]:
                if self.args.cloud not in plan["regions"]:
                    continue
                args = "{}:{}".format(plan["service_type"], plan["service_plan"])
                price_dec = Decimal(plan["regions"][self.args.cloud]["price_usd"])
                if self.args.monthly:
                    price_str = (price_dec * 730).quantize(dformat)
                    price = "${}/mo".format(price_str)
                else:
                    price_str = price_dec.quantize(dformat)
                    price = "${}/h".format(price_str)
                description = self.describe_plan(
                    plan["regions"][self.args.cloud],
                    plan["node_count"],
                    plan["service_plan"],
                )
                print("    {:<28} {:>10}  {}".format(args, price, description))

            if not info["service_plans"]:
                print("    (no plans available)")

            print()

    @arg.project
    @arg.json
    @arg.verbose
    def service__types(self) -> None:
        """List service types"""
        service_types = self.client.get_service_types(project=self.get_project())
        if self.args.json:
            self.print_response(service_types, json=self.args.json)
            return

        output = []
        for service_type, prop in sorted(service_types.items()):
            entry = prop.copy()
            entry["service_type"] = service_type
            output.append(entry)

        self.print_response(output, json=self.args.json, table_layout=[["service_type", "description"]])

        if not self.args.json and self.args.verbose:
            for service_type, service_def in sorted(service_types.items()):
                print("\nService type {!r} options:".format(service_type))
                options = self.collect_user_config_options(service_def["user_config_schema"])
                if not options:
                    print("  (No configurable options)")
                else:
                    for name, spec in sorted(options.items()):
                        default = spec.get("default")
                        default_desc = "(default={!r})".format(default) if default is not None else ""
                        description = spec.get("description", "")
                        full_description = (
                            "{}: {}".format(spec.get("title"), description) if "title" in spec else description
                        )
                        types = spec["type"]
                        if isinstance(types, str) and types == "null":
                            print(
                                "  {full_description}\n"
                                "     => --remove-option {name}".format(
                                    name=name,
                                    full_description=full_description,
                                )
                            )
                        else:
                            if not isinstance(types, list):
                                types = [types]
                            type_str = " or ".join(t for t in types if t != "null")
                            print(
                                "  {full_description}\n"
                                "     => -c {name}=<{type}>  {default}".format(
                                    name=name,
                                    type=type_str,
                                    default=default_desc,
                                    full_description=full_description,
                                )
                            )

    SERVICE_LAYOUT = [
        [
            "service_name",
            "service_type",
            "state",
            "cloud_name",
            "plan",
            "create_time",
            "update_time",
            "notifications",
        ]
    ]
    EXT_SERVICE_LAYOUT = ["service_uri", "disk_space_mb", "user_config.*", "databases", "users"]

    @arg.project
    @arg("service_name", nargs="*", default=[], help="Service name")
    @arg.service_type
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service__list(self) -> None:
        """List services"""
        services = self.client.get_services(project=self.get_project())
        if self.args.service_type is not None:
            services = [s for s in services if s["service_type"] == self.args.service_type]
        if self.args.service_name:
            services = [s for s in services if s["service_name"] in self.args.service_name]

        layout: list[Any] = self.SERVICE_LAYOUT[:]
        if self.args.verbose:
            layout.extend(self.EXT_SERVICE_LAYOUT)

        # Format service notifications
        for service in services:
            service["notifications"] = self._format_service_notifications(service)

        self.print_response(services, format=self.args.format, json=self.args.json, table_layout=layout)

    def _format_service_notifications(self, service: Mapping[str, Any]) -> Sequence[str]:
        """Format service notifications as list of short text elements suitable for table view."""
        if "service_notifications" in service:
            notifications = []
            for notification in service["service_notifications"]:
                if notification["type"] == "service_end_of_life":
                    eol_time = parse_iso8601(notification["metadata"]["service_end_of_life_time"])
                    eol_date = eol_time.date().isoformat()
                    is_urgent = notification["level"] == "warning"
                    upgrade_urgency = "required" if is_urgent else "available"
                    notifications.append(f"EOL: {eol_date} Upgrade {upgrade_urgency}")

            return notifications
        else:
            return []

    def print_service_notifications(self, service_notifications: Sequence[Mapping[str, Any]]) -> None:
        def make_bold(text: str) -> str:
            bold = "\033[1m"
            normal = "\033[0m"
            return bold + text + normal

        for service_notification in service_notifications:
            text = service_notification["message"]
            if service_notification["type"] == "service_end_of_life":
                text += "\nRead more: " + service_notification["metadata"]["end_of_life_help_article_url"]
            print(make_bold(text) if service_notification["level"] == "warning" else text)
            print()

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

    @arg.project
    @arg("--format", help="Format string for output")
    @arg.json
    def static_ip__list(self) -> None:
        """List static IP addresses"""
        resp = self.client.list_static_ip_addresses(project=self.get_project())
        self.print_response(resp, format=self.args.format, json=self.args.json)

    @arg.project
    @arg.cloud_mandatory
    @arg("--format", help="Format string for output")
    @arg.json
    def static_ip__create(self) -> None:
        """Create static IP address"""
        resp = self.client.create_static_ip_address(project=self.get_project(), cloud_name=self.args.cloud)
        self.print_response(resp, format=self.args.format, json=self.args.json, single_item=True)

    @arg.project
    @arg.static_ip_id
    @arg("--service", help="Service name", required=True)
    def static_ip__associate(self) -> None:
        """Associate a static IP address with a service"""
        self.client.associate_static_ip_address(
            project=self.get_project(), static_ip_id=self.args.static_ip_id, service_name=self.args.service
        )

    @arg.project
    @arg.static_ip_id
    def static_ip__dissociate(self) -> None:
        """Dissociate a static IP address from a service"""
        self.client.dissociate_static_ip_address(project=self.get_project(), static_ip_id=self.args.static_ip_id)

    @arg.project
    @arg("--format", help="Format string for output")
    @arg.static_ip_id
    def static_ip__delete(self) -> None:
        """Delete a static IP address"""
        self.client.delete_static_ip_address(project=self.get_project(), static_ip_id=self.args.static_ip_id)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service__get(self) -> None:
        """Show a single service"""

        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)

        # Format service notifications
        service["notifications"] = self._format_service_notifications(service)

        layout: list = self.SERVICE_LAYOUT[:]
        if self.args.verbose:
            ext_layout = list(self.EXT_SERVICE_LAYOUT)
            if service["service_type"] == "kafka":
                connection_info = service["connection_info"]
                user_config = service["user_config"]
                for key in ["kafka_connect", "kafka_rest", "schema_registry"]:
                    if user_config.get(key):
                        key_uri = "{}_uri".format(key)
                        ext_layout.append(key_uri)
                        service[key_uri] = connection_info[key_uri]
            layout.extend(ext_layout)

        if "service_notifications" in service and not self.args.json:
            self.print_service_notifications(service["service_notifications"])
        self.print_response(
            service,
            format=self.args.format,
            json=self.args.json,
            table_layout=layout,
            single_item=True,
        )

        if self.args.verbose and not self.args.json and service.get("node_states"):
            print("Service node states")
            collapsed = []
            layout = [
                "name",
                "state",
                "phase",
                "min",
                "current",
                "max",
                "unit",
                "progress",
            ]
            for node_state in sorted(service["node_states"], key=lambda ns: ns["name"]):
                collapsed.append(
                    {
                        "current": "",
                        "max": "",
                        "min": "",
                        "name": node_state["name"],
                        "phase": "",
                        "progress": "",
                        "state": node_state["state"],
                        "unit": "",
                    }
                )
                for progress_update in node_state["progress_updates"]:
                    progress = ""
                    maxv = progress_update["max"]
                    minv = progress_update["min"]
                    currentv = progress_update["current"]
                    if minv is not None and maxv is not None and currentv is not None:
                        progress = "{} %".format(int(1000 * (currentv - minv) / (maxv - minv)) / 10)
                    collapsed.append(
                        {
                            "current": str(currentv) if currentv is not None else "",
                            "max": str(maxv) if maxv is not None else "",
                            "min": str(minv) if minv is not None else "",
                            "name": node_state["name"],
                            "phase": progress_update["phase"],
                            "progress": progress,
                            "state": "",
                            "unit": progress_update.get("unit") or "",
                        }
                    )
            self.print_response(collapsed, format=self.args.format, json=False, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.json
    def service__backup_list(self) -> None:
        """List backups for service."""
        backups = self.client.get_service_backups(project=self.get_project(), service=self.args.service_name)
        layout = ["backup_name", "backup_time", "data_size", "storage_location"]
        self.print_response(backups, json=self.args.json, table_layout=layout)

    def _get_project_ca(self) -> str:
        return self.client.get_project_ca(project=self.get_project())["certificate"]

    def _get_store_from_args(self) -> Store:
        if self.args.overwrite:
            store = Store.overwrite
        elif self.args.write:
            store = Store.skip
        else:
            store = Store.skip
        return store

    # Check service__connection_info__kcat
    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("-p", "--privatelink-connection-id")
    @arg("-a", "--kafka-authentication-method", choices=("certificate", "sasl"), default="certificate")
    @arg("-u", "--username", default="avnadmin")
    @arg("--ca", default="ca.pem", dest="ca_path")
    @arg("--client-cert", default="service.crt", dest="client_cert_path")
    @arg("--client-key", default="service.key", dest="client_key_path")
    @arg("-w", "--write", action="store_true", help="Save certificate and key files if they don't not exist")
    @arg("-W", "--overwrite", action="store_true", help="Save and overwrite certificate and key files")
    def service__connection_info__kafkacat(self) -> None:
        """kafkacat command string"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        store = self._get_store_from_args()

        if self.args.kafka_authentication_method == "certificate":
            ci = KafkaCertificateConnectionInfo.from_service(
                service,
                route=self._get_route_from_args(),
                privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
                username=self.args.username,
            )
            cmd = ci.kcat(
                "kafkacat",
                store,
                get_project_ca=self._get_project_ca,
                ca_path=self.args.ca_path,
                client_cert_path=self.args.client_cert_path,
                client_key_path=self.args.client_key_path,
            )
        elif self.args.kafka_authentication_method == "sasl":
            sasl_ci = KafkaSASLConnectionInfo.from_service(
                service,
                route=self._get_route_from_args(),
                privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
                username=self.args.username,
            )
            cmd = sasl_ci.kcat(
                "kafkacat",
                store,
                get_project_ca=self._get_project_ca,
                ca_path=self.args.ca_path,
            )
        else:
            raise NotImplementedError(self.args.kafka_authentication_method)

        print(" ".join(cmd))

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("-p", "--privatelink-connection-id")
    @arg("-a", "--kafka-authentication-method", choices=("certificate", "sasl"), default="certificate")
    @arg("-u", "--username", default="avnadmin")
    @arg("--ca", default="ca.pem", dest="ca_path")
    @arg("--client-cert", default="service.crt", dest="client_cert_path")
    @arg("--client-key", default="service.key", dest="client_key_path")
    @arg("-w", "--write", action="store_true", help="Save certificate and key files if they don't not exist")
    @arg("-W", "--overwrite", action="store_true", help="Save and overwrite certificate and key files")
    def service__connection_info__kcat(self) -> None:
        """kcat command string"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        store = self._get_store_from_args()

        if self.args.kafka_authentication_method == "certificate":
            ci = KafkaCertificateConnectionInfo.from_service(
                service,
                route=self._get_route_from_args(),
                privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
                username=self.args.username,
            )
            cmd = ci.kcat(
                "kcat",
                store,
                get_project_ca=self._get_project_ca,
                ca_path=self.args.ca_path,
                client_cert_path=self.args.client_cert_path,
                client_key_path=self.args.client_key_path,
            )
        elif self.args.kafka_authentication_method == "sasl":
            sasl_ci = KafkaSASLConnectionInfo.from_service(
                service,
                route=self._get_route_from_args(),
                privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
                username=self.args.username,
            )
            cmd = sasl_ci.kcat(
                "kcat",
                store,
                get_project_ca=self._get_project_ca,
                ca_path=self.args.ca_path,
            )
        else:
            raise NotImplementedError(self.args.kafka_authentication_method)

        print(" ".join(cmd))

    def _get_route_from_args(self) -> str:
        route = self.args.route
        if route is None:
            if self.args.privatelink_connection_id is None:
                return "dynamic"
            return "privatelink"
        return route

    def _get_usage_from_args(self) -> str:
        if self.args.usage is None:
            usage = "replica" if self.args.replica else "primary"
        else:
            if self.args.replica:
                raise argx.UserError("--usage and --replica cannot be used simultaneously")
            usage = self.args.usage
        return usage

    def _get_privatelink_connection_id_from_args(self) -> object | str:
        privatelink_connection_id = self.args.privatelink_connection_id
        if privatelink_connection_id is None:
            return UNDEFINED
        if self.args.route not in {None, "privatelink"}:
            raise argx.UserError(f"-p/--privatelink-connection-id cannot be used with route {self.args.route}")
        return privatelink_connection_id

    def _get_connection_info_pg(self, service_name: str) -> PGConnectionInfo:
        """PostgreSQL connection info"""
        service = self.client.get_service(project=self.get_project(), service=service_name)

        return PGConnectionInfo.from_service(
            service,
            route=self._get_route_from_args(),
            usage=self._get_usage_from_args(),
            privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
            username=self.args.username,
            dbname=self.args.dbname,
            sslmode=self.args.sslmode,
        )

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="avnadmin")
    @arg("-d", "--dbname", default="defaultdb")
    @arg("--sslmode", default="require", choices=("require", "verify-ca", "verify-full", "disable", "allow", "prefer"))
    def service__connection_info__psql(self) -> None:
        """psql command string"""
        ci = self._get_connection_info_pg(self.args.service_name)
        cmd = ci.psql()
        print(" ".join(cmd))

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="avnadmin")
    @arg("-d", "--dbname", default="defaultdb")
    @arg("--sslmode", default="require", choices=("require", "verify-ca", "verify-full", "disable", "allow", "prefer"))
    def service__connection_info__pg__uri(self) -> None:
        """PostgreSQL service URI"""
        ci = self._get_connection_info_pg(self.args.service_name)
        print(ci.uri())

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="avnadmin")
    @arg("-d", "--dbname", default="defaultdb")
    @arg("--sslmode", default="require", choices=("require", "verify-ca", "verify-full", "disable", "allow", "prefer"))
    def service__connection_info__pg__string(self) -> None:
        """PostgreSQL connection string"""
        ci = self._get_connection_info_pg(self.args.service_name)
        print(ci.connection_string())

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="avnadmin")
    @arg("-d", "--dbname", default="defaultdb")
    @arg("--sslmode", default="require", choices=("require", "verify-ca", "verify-full", "disable", "allow", "prefer"))
    def service__connection_info__alloydbomni__uri(self) -> None:
        """AlloyDB Omni service URI"""
        ci = self._get_connection_info_pg(self.args.service_name)
        print(ci.uri())

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="avnadmin")
    @arg("-d", "--dbname", default="defaultdb")
    @arg("--sslmode", default="require", choices=("require", "verify-ca", "verify-full", "disable", "allow", "prefer"))
    def service__connection_info__alloydbomni__string(self) -> None:
        """AlloyDB Omni connection string"""
        ci = self._get_connection_info_pg(self.args.service_name)
        print(ci.connection_string())

    @arg.project
    @arg.service_name
    @arg("-r", "--route", choices=("dynamic", "privatelink", "public"))
    @arg("--usage", choices=("primary", "replica"))
    @arg("-p", "--privatelink-connection-id")
    @arg("--replica", action="store_true")
    @arg("-u", "--username", default="default")
    @arg("-d", "--db")
    def service__connection_info__redis__uri(self) -> None:
        """Redis connection string"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)

        ci = RedisConnectionInfo.from_service(
            service,
            route=self._get_route_from_args(),
            usage=self._get_usage_from_args(),
            privatelink_connection_id=self._get_privatelink_connection_id_from_args(),
            username=self.args.username,
            db=self.args.db,
        )
        print(ci.uri())

    @optional_auth
    @arg.project
    @arg.service_name
    @arg(
        "arg",
        nargs="*",
        help="Pass arguments directly for service client, use '--' to separate from avn args",
        default=[],
    )
    def service__cli(self) -> None:
        """Open interactive shell to given service (if supported)"""
        if "://" in self.args.service_name:
            url = self.args.service_name
        else:
            if not self.client.auth_token:
                raise argx.UserError("not authenticated: please login first with 'avn user login'")
            service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
            url = service["service_uri"]

        match = re.match("([a-z]+\\+)?([a-z]+)://", url)
        service_type = match and match.group(2)
        if service_type == "influxdb":
            command, params, env = self._build_influx_start_info(url)
        elif service_type == "postgres":
            command, params, env = self._build_psql_start_info(url)
        elif service_type == "rediss":
            command, params, env = self._build_redis_start_info(url)
        elif service_type == "mysql":
            command, params, env = self._build_mysql_start_info(url)
        else:
            raise argx.UserError(
                "Unsupported service type {}. Only InfluxDB, PostgreSQL, and Redis are supported".format(service_type)
            )

        try:
            os.execvpe(command, [command] + params + self.args.arg, dict(os.environ, **env))
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            raise argx.UserError("Executable '{}' is not available, cannot launch {} client".format(command, service_type))

    def _build_influx_start_info(self, url: str) -> tuple[str, list, Mapping]:
        info = urlparse(url)
        params = [
            "-host",
            info.hostname,
            "-port",
            str(info.port),
            "-database",
            info.path.lstrip("/"),
            "-username",
            info.username,
            "-ssl",
        ]
        return "influx", params, {"INFLUX_PASSWORD": info.password}

    def _build_psql_start_info(self, url: str) -> tuple[str, list, Mapping]:
        pw_pattern = "([a-z\\+]+://[^:]+):([^@]+)@(.*)"
        match = re.match(pw_pattern, url)
        connect_info = re.sub(pw_pattern, "\\1@\\3", url)
        return "psql", [connect_info], {"PGPASSWORD": match.group(2) if match else None}

    def _build_mysql_start_info(self, url: str) -> tuple[str, list, Mapping]:
        info = urlparse(url)
        params = [
            "-h",
            info.hostname,
            "-P",
            str(info.port),
            "-u",
            info.username,
        ]
        return "mysql", params, {"MYSQL_PWD": info.password}

    def _build_redis_start_info(self, url: str) -> tuple[str, list, Mapping]:
        info = urlparse(url)
        params = [
            "--tls",
            "-h",
            info.hostname,
            "-p",
            str(info.port),
            "--user",
            info.username,
        ]
        return "redis-cli", params, {"REDISCLI_AUTH": info.password}

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service__credentials_reset(self) -> None:
        """Reset service credentials"""
        service = self.client.reset_service_credentials(project=self.get_project(), service=self.args.service_name)
        layout: list = [
            [
                "service_name",
                "service_type",
                "state",
                "cloud_name",
                "plan",
                "create_time",
                "update_time",
            ]
        ]
        if self.args.verbose:
            layout.extend(["service_uri", "user_config.*"])
        self.print_response([service], format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg(
        "--period",
        help="Metrics period",
        default="hour",
        choices=["hour", "day", "week", "month", "year"],
    )
    def service__metrics(self) -> None:
        """Get service metrics"""
        metrics = self.client.get_service_metrics(
            project=self.get_project(), service=self.args.service_name, period=self.args.period
        )
        print(jsonlib.dumps(metrics, indent=2, sort_keys=True))

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg("--dbname", help="Service database name", required=True)
    @arg("--username", help="Service username")
    @arg("--pool-size", type=int, help="Connection pool size")
    @arg("--pool-mode", help="Connection pool mode")
    @arg.json
    def service__connection_pool_create(self) -> None:
        """Create a connection pool for a given PostgreSQL service"""
        self.client.create_service_connection_pool(
            project=self.get_project(),
            service=self.args.service_name,
            pool_name=self.args.pool_name,
            dbname=self.args.dbname,
            username=self.args.username,
            pool_size=self.args.pool_size,
            pool_mode=self.args.pool_mode,
        )

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg("--dbname", help="Service database name")
    @arg("--username", help="Service username (set to empty string to remove the pool username)")
    @arg("--pool-size", type=int, help="Connection pool size")
    @arg("--pool-mode", help="Connection pool mode")
    @arg.json
    def service__connection_pool_update(self) -> None:
        """Update a connection pool for a given PostgreSQL service"""
        kwargs = {
            "project": self.get_project(),
            "service": self.args.service_name,
            "pool_name": self.args.pool_name,
            "dbname": self.args.dbname,
            "pool_size": self.args.pool_size,
            "pool_mode": self.args.pool_mode,
        }

        if self.args.username is not None:
            kwargs["username"] = self.args.username if self.args.username != "" else None

        self.client.update_service_connection_pool(**kwargs)

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg.json
    def service__connection_pool_delete(self) -> None:
        """Delete a connection pool from a given service"""
        self.client.delete_service_connection_pool(
            project=self.get_project(),
            service=self.args.service_name,
            pool_name=self.args.pool_name,
        )

    @arg.project
    @arg.service_name
    @arg.verbose
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.json
    def service__connection_pool_list(self) -> None:
        """List PGBouncer pools for a service"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        layout = ["pool_name", "database", "username", "pool_mode", "pool_size"]
        if self.args.verbose:
            layout.append("connection_uri")
        self.print_response(
            service["connection_pools"],
            format=self.args.format,
            json=self.args.json,
            table_layout=[layout],
        )

    @arg.project
    @arg.service_name
    @arg("--dbname", help="Service database name", required=True)
    @arg.json
    def service__database_create(self) -> None:
        """Create a database within a given service"""
        self.client.create_service_database(
            project=self.get_project(), service=self.args.service_name, dbname=self.args.dbname
        )

    @arg.project
    @arg.service_name
    @arg("--dbname", help="Service database name", required=True)
    @arg.json
    def service__database_delete(self) -> None:
        """Delete a database within a given service"""
        self.client.delete_service_database(
            project=self.get_project(), service=self.args.service_name, dbname=self.args.dbname
        )

    @arg.project
    @arg.service_name
    def service__maintenance_start(self) -> None:
        """Start service maintenance updates"""
        response = self.client.start_service_maintenance(project=self.get_project(), service=self.args.service_name)
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg.json
    def service__migration_status(self) -> None:
        """Get migration status"""
        response = self.client.get_service_migration_status(project=self.get_project(), service=self.args.service_name)
        layout = ["status", "method", "error"]
        self.print_response(
            response["migration"],
            json=self.args.json,
            single_item=True,
            table_layout=layout,
        )

    def _parse_access_control(self) -> Mapping[str, Any]:
        arg_vars = vars(self.args)
        result = {key: arg_vars[key].split() for key in REDIS_VALKEY_ACL_ARGS if arg_vars[key] is not None}
        for key in ["m3_group"]:
            value = arg_vars[key]
            if value is not None:
                result[key] = value
        return result

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg("--m3-group", help="Service user group")
    @arg("--redis-acl-keys", help="ACL rules for keys (Redis only)")
    @arg("--redis-acl-commands", help="ACL rules for commands (Redis only)")
    @arg("--redis-acl-categories", help="ACL rules for command categories (Redis only)")
    @arg("--redis-acl-channels", help="ACL rules for channels (Redis only)")
    @arg("--valkey-acl-keys", help="ACL rules for keys (Valkey only)")
    @arg("--valkey-acl-commands", help="ACL rules for commands (Valkey only)")
    @arg("--valkey-acl-categories", help="ACL rules for command categories (Valkey only)")
    @arg("--valkey-acl-channels", help="ACL rules for channels (Valkey only)")
    @arg.json
    def service__user_create(self) -> None:
        """Create service user"""
        extra_params = {}
        access_control = self._parse_access_control()
        if access_control:
            extra_params = {"access_control": access_control}
        self.client.create_service_user(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
            extra_params=extra_params,
        )

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg.json
    def service__user_delete(self) -> None:
        """Delete a service user"""
        self.client.delete_service_user(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
        )

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.json
    def service__user_list(self) -> None:
        """List service users"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        layout = [["username", "type"]]
        if service["service_type"] == "redis":
            layout[0].extend(
                [
                    "access_control.redis_acl_keys",
                    "access_control.redis_acl_commands",
                    "access_control.redis_acl_categories",
                    "access_control.redis_acl_channels",
                ]
            )
        self.print_response(
            service["users"],
            format=self.args.format,
            json=self.args.json,
            table_layout=layout,
        )

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.json
    def service__user_get(self) -> None:
        """Get details for a single user"""
        user = self.client.get_service_user(
            project=self.get_project(), service=self.args.service_name, username=self.args.username
        )
        layout = [["username", "type"]]
        for field in (
            "redis_acl_keys",
            "redis_acl_commands",
            "redis_acl_categories",
            "redis_acl_channels",
        ):
            if field in user.get("access_control", {}):
                layout[0].append(f"access_control.{field}")
        self.print_response(user, single_item=True, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg(
        "-d",
        "--target-directory",
        help="Directory to write credentials to",
        required=False,
        default=os.getcwd(),
    )
    @arg("-p", "--password", help="Truststore password", default="changeit")
    def service__user_kafka_java_creds(self) -> None:
        """Download user certificate/key/CA certificate and create a Java keystore/truststore/properties from them"""
        self.service__user_creds_download()
        # First create the truststore
        subprocess.check_call(
            [
                "keytool",
                "-importcert",
                "-alias",
                "Aiven CA",
                "-keystore",
                os.path.join(self.args.target_directory, "client.truststore.jks"),
                "-storepass",
                self.args.password,
                "-file",
                os.path.join(self.args.target_directory, "ca.pem"),
                "-noprompt",
            ]
        )
        # Then create the keystore
        subprocess.check_call(
            [
                "openssl",
                "pkcs12",
                "-export",
                "-out",
                os.path.join(self.args.target_directory, "client.keystore.p12"),
                "-inkey",
                os.path.join(self.args.target_directory, "service.key"),
                "-in",
                os.path.join(self.args.target_directory, "service.cert"),
                "-certfile",
                os.path.join(self.args.target_directory, "ca.pem"),
                "-passout",
                "pass:{}".format(self.args.password),
            ]
        )
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        with open(os.path.join(self.args.target_directory, "client.properties"), "w", encoding="utf-8") as fp:
            properties = """\
bootstrap.servers={service_uri}
security.protocol=SSL
ssl.protocol=TLS
ssl.key.password={password}
ssl.keystore.location={keypath}/client.keystore.p12
ssl.keystore.password={password}
ssl.keystore.type=PKCS12
ssl.truststore.location={keypath}/client.truststore.jks
ssl.truststore.password={password}
ssl.truststore.type=JKS
            """.format(
                keypath=os.path.abspath(self.args.target_directory),
                password=self.args.password,
                service_uri=service["service_uri"],
            )
            fp.write(properties)

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg(
        "-d",
        "--target-directory",
        help="Directory to write credentials to",
        required=False,
        default=os.getcwd(),
    )
    def service__user_creds_download(self) -> None:
        """Download service user certificate/key/CA certificate"""
        project_name = self.get_project()

        if not os.path.exists(self.args.target_directory):
            os.makedirs(self.args.target_directory)

        error_messages = []
        downloaded_items = []

        try:
            result = self.client.get_project_ca(project=project_name)
            with open(os.path.join(self.args.target_directory, "ca.pem"), "w", encoding="utf-8") as fp:
                fp.write(result["certificate"])
            downloaded_items.append("CA certificate")
        except client.Error as ex:
            error_messages.append("Project '{}' CA get failed: {}".format(project_name, ex.response.text))

        missing_user_items = []
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        matched_service_users = [s_user for s_user in service["users"] if s_user["username"] == self.args.username]

        if not matched_service_users:
            error_messages.append(
                "The value passed as argument --username does not match any service user,\n"
                + "therefore the service certificate key pair cannot be obtained.\n\n"
                + "To get the service users and their passwords, type:\n"
                + "   avn service user-list --format '{{username}} {{password}}' --project {} {}".format(
                    project_name, self.args.service_name
                )
            )

        else:
            user = matched_service_users[0]
            cert = user.get("access_cert")
            if cert is None:
                missing_user_items.append("certificate")
            else:
                with open(os.path.join(self.args.target_directory, "service.cert"), "w", encoding="utf-8") as fp:
                    fp.write(cert)
                downloaded_items.append("certificate")

            key = user.get("access_key")
            if key is None:
                missing_user_items.append("key")
            else:
                with open(os.path.join(self.args.target_directory, "service.key"), "w", encoding="utf-8") as fp:
                    fp.write(key)
                downloaded_items.append("key")

            if downloaded_items:
                print("Downloaded to directory '{}': {}".format(self.args.target_directory, ", ".join(downloaded_items)))
                print()

            if missing_user_items:
                missing_items_str = " and ".join(missing_user_items)
                error_messages.append("The user '{}' does not have {}".format(self.args.username, missing_items_str))

        if error_messages:
            print()
            raise argx.UserError(". ".join(error_messages))

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg.json
    def service__user_creds_acknowledge(self) -> None:
        """Acknowledge that service user certificates have been updated"""
        self.client.acknowledge_service_user_certificate(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
        )

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg("--new-password", help="New password for service user")
    @arg.json
    def service__user_password_reset(self) -> None:
        """Reset service user password"""
        self.client.reset_service_user_password(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
            password=self.args.new_password,
        )

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg("--m3-group", help="Service user group")
    @arg("--redis-acl-keys", help="ACL rules for keys (Redis only)")
    @arg("--redis-acl-commands", help="ACL rules for commands (Redis only)")
    @arg("--redis-acl-categories", help="ACL rules for command categories (Redis only)")
    @arg("--redis-acl-channels", help="ACL rules for channels (Redis only)")
    @arg("--valkey-acl-keys", help="ACL rules for keys (Valkey only)")
    @arg("--valkey-acl-commands", help="ACL rules for commands (Valkey only)")
    @arg("--valkey-acl-categories", help="ACL rules for command categories (Valkey only)")
    @arg("--valkey-acl-channels", help="ACL rules for channels (Valkey only)")
    @arg.json
    def service__user_set_access_control(self) -> None:
        """Set Redis/Valkey service user access control"""
        access_control = self._parse_access_control()
        self.client.set_service_user_access_control(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
            access_control=access_control,
        )

    @arg.project
    @arg.json
    def service__integration_endpoint_types_list(self) -> None:
        """List all available integration endpoint types for given project"""
        endpoint_types = self.client.get_service_integration_endpoint_types(self.get_project())
        layout = ["title", "endpoint_type", "service_types"]
        self.print_response(endpoint_types, json=self.args.json, table_layout=layout)

    @arg.project
    @arg("-d", "--endpoint-name", help="Integration endpoint name", required=True)
    @arg("-t", "--endpoint-type", help="Integration endpoint type", required=True)
    @arg.user_config_json()
    @arg.user_config
    @arg.json
    def service__integration_endpoint_create(self) -> None:
        """Create a service integration endpoint"""
        if self.args.user_config_json:
            user_config = self.args.user_config_json
        elif self.args.user_config:
            project = self.get_project()
            user_config_schema = self._get_endpoint_user_config_schema(
                project=project, endpoint_type_name=self.args.endpoint_type
            )
            user_config = self.create_user_config(user_config_schema)
        else:
            user_config = {}

        self.client.create_service_integration_endpoint(
            project=self.get_project(),
            endpoint_name=self.args.endpoint_name,
            endpoint_type=self.args.endpoint_type,
            user_config=user_config,
        )

    @arg.project
    @arg("endpoint_id", help="Service integration endpoint ID")
    @arg.user_config
    @arg.user_config_json()
    @arg.json
    def service__integration_endpoint_update(self) -> None:
        """Update a service integration endpoint"""
        if self.args.user_config_json:
            user_config = self.args.user_config_json
        elif self.args.user_config:
            project = self.get_project()
            integration_endpoints = self.client.get_service_integration_endpoints(project=self.get_project())
            endpoint_type = None
            for endpoint in integration_endpoints:
                if endpoint["endpoint_id"] == self.args.endpoint_id:
                    endpoint_type = endpoint["endpoint_type"]

            if not endpoint_type:
                raise argx.UserError("Endpoint id does not exist")

            user_config_schema = self._get_endpoint_user_config_schema(project=project, endpoint_type_name=endpoint_type)
            user_config = self.create_user_config(user_config_schema)
        else:
            user_config = {}

        self.client.update_service_integration_endpoint(
            project=self.get_project(),
            endpoint_id=self.args.endpoint_id,
            user_config=user_config,
        )

    @arg.project
    @arg("endpoint_id", help="Service integration endpoint ID")
    @arg.json
    def service__integration_endpoint_delete(self) -> None:
        """Delete a service integration endpoint"""
        self.client.delete_service_integration_endpoint(
            project=self.get_project(),
            endpoint_id=self.args.endpoint_id,
        )

    @arg.project
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.verbose
    @arg.json
    def service__integration_endpoint_list(self) -> None:
        """List service integration endpoints"""
        service_integration_endpoints = self.client.get_service_integration_endpoints(project=self.get_project())
        layout: list = [["endpoint_id", "endpoint_name", "endpoint_type"]]
        if self.args.verbose:
            layout.extend(["user_config"])
        self.print_response(
            service_integration_endpoints,
            format=self.args.format,
            json=self.args.json,
            table_layout=layout,
        )

    @arg.project
    @arg.json
    def service__integration_types_list(self) -> None:
        """List all available integration types for given project"""
        endpoint_types = self.client.get_service_integration_types(self.get_project())
        layout = [
            "integration_type",
            "dest_description",
            "dest_service_type",
            "source_description",
            "source_service_types",
        ]
        self.print_response(endpoint_types, json=self.args.json, table_layout=layout)

    @arg.project
    @arg("-t", "--integration-type", help="Integration type", required=True)
    @arg("-s", "--source-service", help="Source service name")
    @arg("-d", "--dest-service", help="Destination service name")
    @arg("-S", "--source-endpoint-id", help="Source integration endpoint id")
    @arg("-D", "--dest-endpoint-id", help="Destination integration endpoint id")
    @arg.user_config
    @arg.user_config_json()
    @arg.json
    def service__integration_create(self) -> None:
        """Create a service integration"""
        if self.args.user_config_json:
            user_config = self.args.user_config_json
        elif self.args.user_config:
            project = self.get_project()
            user_config_schema = self._get_integration_user_config_schema(
                project=project, integration_type_name=self.args.integration_type
            )
            user_config = self.create_user_config(user_config_schema)
        else:
            user_config = {}

        self.client.create_service_integration(
            project=self.get_project(),
            source_service=self.args.source_service,
            dest_service=self.args.dest_service,
            source_endpoint_id=self.args.source_endpoint_id,
            dest_endpoint_id=self.args.dest_endpoint_id,
            integration_type=self.args.integration_type,
            user_config=user_config,
        )

    @arg.project
    @arg("integration_id", help="Service integration ID")
    @arg.user_config
    @arg.user_config_json()
    @arg.json
    def service__integration_update(self) -> None:
        """Update a service integration"""
        if self.args.user_config_json:
            user_config = self.args.user_config_json
        elif self.args.user_config:
            project = self.get_project()
            integration = self.client.get_service_integration(
                project=project,
                integration_id=self.args.integration_id,
            )
            integration_type = ""
            if integration["service_integration_id"] == self.args.integration_id:
                integration_type = integration["integration_type"]
            user_config_schema = self._get_integration_user_config_schema(
                project=project, integration_type_name=integration_type
            )
            user_config = self.create_user_config(user_config_schema)
        else:
            user_config = {}

        self.client.update_service_integration(
            project=self.get_project(),
            integration_id=self.args.integration_id,
            user_config=user_config,
        )

    @arg.project
    @arg("integration_id", help="Service integration ID")
    @arg.json
    def service__integration_delete(self) -> None:
        """Delete a service integration"""
        self.client.delete_service_integration(
            project=self.get_project(),
            integration_id=self.args.integration_id,
        )

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.verbose
    @arg.json
    def service__integration_list(self) -> None:
        """List service integrations"""
        service_integrations = self.client.get_service_integrations(
            project=self.get_project(), service=self.args.service_name
        )
        for item in service_integrations:
            item["service_integration_id"] = item["service_integration_id"] or "(integration not enabled)"
            item["source"] = item["source_service"] or item["source_endpoint_id"]
            item["dest"] = item["dest_service"] or item["dest_endpoint_id"]

        layout: list = [
            [
                "service_integration_id",
                "source",
                "dest",
                "integration_type",
                "enabled",
                "active",
                "description",
            ]
        ]
        if self.args.verbose:
            layout.extend(["source_project", "dest_project"])
        self.print_response(
            service_integrations,
            format=self.args.format,
            json=self.args.json,
            table_layout=layout,
        )

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

    @arg.project
    @arg.service_name
    @arg.json
    def service__database_list(self) -> None:
        """List service databases"""
        service = self.client.list_databases(project=self.get_project(), service=self.args.service_name)
        database_names = [result["database_name"] for result in service["databases"]]
        layout = [["database"]]
        self.print_response(database_names, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{calls} {total_time}'")
    @arg.verbose
    @arg.json
    def service__queries_reset(self) -> None:
        """Reset service query statistics"""
        queries = self.client.reset_service_query_stats(project=self.get_project(), service=self.args.service_name)
        self.print_response(queries, format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{query} {backend_start}'")
    @arg.verbose
    @arg.json
    def service__current_queries(self) -> None:
        """List current service connections/queries"""
        queries = self.client.get_service_current_queries(project=self.get_project(), service=self.args.service_name)
        layout: list = [["pid", "query", "query_duration", "client_addr", "application_name"]]
        if self.args.verbose:
            layout.extend(
                [
                    "datid",
                    "datname",
                    "pid",
                    "usesysid",
                    "usename",
                    "application_name",
                    "client_addr",
                    "client_hostname",
                    "client_port",
                    "backend_start",
                    "xact_start",
                    "query_start",
                    "state_change",
                    "waiting",
                    "state",
                    "backend_xid",
                    "backend_xmin",
                    "query",
                    "query_duration",
                ]
            )
        self.print_response(queries, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{calls} {total_time}'")
    @arg.verbose
    @arg.json
    def service__queries(self) -> None:
        """List service query statistics"""
        project = self.get_project()
        service = self.args.service_name
        service_type = self.client.get_service(project, service)["service_type"]
        queries = self.client.get_service_query_stats(project=project, service=service, service_type=service_type)
        layout: list = (
            [
                [
                    "query",
                    "max_time",
                    "stddev_time",
                    "min_time",
                    "mean_time",
                    "rows",
                    "calls",
                    "total_time",
                ]
            ]
            if service_type in ("pg", "alloydbomni")
            else [
                [
                    "digest_text",
                    "max_timer_wait",
                    "min_timer_wait",
                    "avg_timer_wait",
                    "sum_rows_affected",
                    "sum_rows_sent",
                    "count_star",
                    "sum_timer_wait",
                ]
            ]
        )
        if self.args.verbose:
            layout.extend(
                [
                    "database_name",
                    "user_name",
                    "blk_read_time",
                    "blk_write_time",
                    "local_blks_dirtied",
                    "local_blks_hit",
                    "local_blks_read",
                    "local_blks_written",
                    "shared_blks_dirtied",
                    "shared_blks_hit",
                    "shared_blks_read",
                    "shared_blks_written",
                    "temp_blks_read",
                    "temp_blks_written",
                ]
                if service_type in ("pg", "alloydbomni")
                else [
                    "digest",
                    "first_seen",
                    "last_seen",
                    "quantile_95",
                    "quantile_99",
                    "quantile_999",
                    "query_sample_seen",
                    "query_sample_text",
                    "query_sample_timer_wait",
                    "schema_name",
                    "sum_created_tmp_disk_tables",
                    "sum_created_tmp_tables",
                    "sum_errors",
                    "sum_lock_time",
                    "sum_no_good_index_used",
                    "sum_no_index_used",
                    "sum_rows_examined",
                    "sum_select_full_join",
                    "sum_select_full_range_join",
                    "sum_select_range",
                    "sum_select_range_check",
                    "sum_select_scan",
                    "sum_sort_merge_passes",
                    "sum_sort_range",
                    "sum_sort_rows",
                    "sum_sort_scan",
                    "sum_warnings",
                ]
            )
        self.print_response(queries, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service__index_list(self) -> None:
        """List Elasticsearch service indexes"""
        indexes = self.client.get_service_indexes(project=self.get_project(), service=self.args.service_name)
        layout = [["index_name", "number_of_shards", "number_of_replicas", "create_time"]]
        self.print_response(indexes, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.index_name
    def service__index_delete(self) -> None:
        """Delete Elasticsearch service index"""
        self.client.delete_service_index(
            project=self.get_project(),
            service=self.args.service_name,
            index_name=self.args.index_name,
        )

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service__m3__namespace__list(self) -> None:
        """List M3 namespaces"""
        namespaces = self.client.list_m3_namespaces(project=self.get_project(), service=self.args.service_name)
        layout = [
            [
                "name",
                "type",
                "resolution",
                "retention_period_duration",
                "blocksize_duration",
                "block_data_expiry_duration",
                "buffer_future_duration",
                "buffer_past_duration",
                "writes_to_commitlog",
            ]
        ]
        if not self.args.json:
            # Fix optional fields, flatten for output
            def _f(ns: dict[str, Any]) -> dict[str, str]:
                o = ns.get("options", {})
                ro = o.get("retention_options", {})
                return {
                    "name": ns["name"],
                    "type": ns["type"],
                    "resolution": ns.get("resolution", ""),
                    "retention_period_duration": ro.get("retention_period_duration", ""),
                    "blocksize_duration": ro.get("blocksize_duration", ""),
                    "block_data_expiry_duration": ro.get("block_data_expiry_duration", ""),
                    "buffer_future_duration": ro.get("buffer_future_duration", ""),
                    "buffer_past_duration": ro.get("buffer_past_duration", ""),
                    "writes_to_commitlog": o.get("writes_to_commitlog", ""),
                }

            namespaces = [_f(ns) for ns in namespaces]
        self.print_response(namespaces, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.ns_name
    def service__m3__namespace__delete(self) -> None:
        """Delete M3 namespaces"""
        try:
            self.client.delete_m3_namespace(
                project=self.get_project(), service=self.args.service_name, ns_name=self.args.ns_name
            )
        except KeyError as ex:  # namespace does not exist
            raise argx.UserError(ex)

    @arg.project
    @arg.service_name
    @arg.ns_name
    @arg.ns_type
    @arg.ns_retention_mandatory
    @arg.ns_resolution
    @arg.ns_blocksize_dur
    @arg.ns_block_data_expiry_dur
    @arg.ns_buffer_future_dur
    @arg.ns_buffer_past_dur
    @arg.ns_writes_to_commitlog
    def service__m3__namespace__add(self) -> None:
        """Add M3 namespaces"""
        try:
            self.client.add_m3_namespace(
                project=self.get_project(),
                service=self.args.service_name,
                ns_name=self.args.ns_name,
                ns_type=self.args.ns_type,
                ns_ret=self.args.ns_retention,
                ns_res=self.args.ns_resolution,
                ns_blocksize_dur=self.args.ns_blocksize_dur,
                ns_block_data_expiry_dur=self.args.ns_block_data_expiry_dur,
                ns_buffer_future_dur=self.args.ns_buffer_future_dur,
                ns_buffer_past_dur=self.args.ns_buffer_past_dur,
                ns_writes_to_commitlog=convert_str_to_value(
                    schema={"type": ["boolean"]}, value=self.args.ns_writes_to_commitlog
                ),
            )
        except ValueError as ex:  # namespace argument validations
            raise argx.UserError(ex)

    @arg.project
    @arg.service_name
    @arg.ns_name
    @arg.ns_retention
    @arg.ns_resolution
    @arg.ns_blocksize_dur
    @arg.ns_block_data_expiry_dur
    @arg.ns_buffer_future_dur
    @arg.ns_buffer_past_dur
    @arg.ns_writes_to_commitlog
    def service__m3__namespace__update(self) -> None:
        """Add M3 namespaces"""
        try:
            self.client.update_m3_namespace(
                project=self.get_project(),
                service=self.args.service_name,
                ns_name=self.args.ns_name,
                ns_ret=self.args.ns_retention,
                ns_res=self.args.ns_resolution,
                ns_blocksize_dur=self.args.ns_blocksize_dur,
                ns_block_data_expiry_dur=self.args.ns_block_data_expiry_dur,
                ns_buffer_future_dur=self.args.ns_buffer_future_dur,
                ns_buffer_past_dur=self.args.ns_buffer_past_dur,
                ns_writes_to_commitlog=convert_str_to_value(
                    schema={"type": ["boolean"]}, value=self.args.ns_writes_to_commitlog
                ),
            )
        except (KeyError, ValueError) as ex:  # namespace does not exist, argument validations
            raise argx.UserError(ex)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service__topic_list(self) -> None:
        """List Kafka service topics"""
        topics = self.client.list_service_topics(project=self.get_project(), service=self.args.service_name)
        for topic in topics:
            if topic["retention_hours"] == -1:
                topic["retention_hours"] = "unlimited"
            if not self.args.json:
                topic["tags"] = [f"{t['key']}={t['value']}" for t in topic["tags"]]
        layout = [
            [
                "topic_name",
                "partitions",
                "replication",
                "min_insync_replicas",
                "retention_bytes",
                "retention_hours",
                "cleanup_policy",
                "tags",
            ]
        ]
        self.print_response(topics, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.topic
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    @arg.verbose
    def service__topic_get(self) -> None:
        """Get Kafka service topic"""
        topic = self.client.get_service_topic(
            project=self.get_project(), service=self.args.service_name, topic=self.args.topic
        )
        has_remote_size = False
        for p in topic["partitions"]:
            p["groups"] = len(p["consumer_groups"])
            if "remote_size" in p and not has_remote_size:
                has_remote_size = True
        is_tiered = "remote_storage_enable" in topic["config"] and topic["config"]["remote_storage_enable"]["value"]

        cgroups = []
        for p in topic["partitions"]:
            for cg in p["consumer_groups"]:
                if None not in {p["latest_offset"], cg["offset"]}:
                    lag = p["latest_offset"] - cg["offset"]
                else:
                    lag = "UNDEFINED"
                cgroups.append(
                    {
                        "partition": p["partition"],
                        "consumer_group": cg["group_name"],
                        "offset": cg["offset"],
                        "lag": lag,
                    }
                )

        if self.args.json:
            # If JSON output is requested, output the entire object in a single step
            self.print_response(
                {"partitions": topic["partitions"], "consumer_groups": cgroups},
                json=True,
            )
        else:
            if is_tiered and has_remote_size:
                layout = [["partition", "isr", "size", "remote_size", "earliest_offset", "latest_offset", "groups"]]
            else:
                layout = [["partition", "isr", "size", "earliest_offset", "latest_offset", "groups"]]

            self.print_response(
                topic["partitions"],
                format=self.args.format,
                json=self.args.json,
                table_layout=layout,
            )
            print()

            if not cgroups:
                print("(No consumer groups)")
            else:
                self.print_response(
                    cgroups,
                    format=self.args.format,
                    json=self.args.json,
                    table_layout=[["partition", "consumer_group", "offset", "lag"]],
                )

    @arg.project
    @arg.service_name
    @arg(
        "--operation",
        help="Task operation",
        choices=["migration_check", "upgrade_check"],
        default="upgrade_check",
    )
    @arg(
        "--target-version",
        help="Upgrade target version",
        type=int,
        required=False,
    )
    @arg(
        "--source-service-uri",
        help="Migration: source URI for migration",
        required=False,
    )
    @arg(
        "--ignore-dbs",
        help="Migration: comma-separated list of databases to be ignored (MySQL only)",
        required=False,
    )
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service__task_create(self) -> None:
        """Create a service task"""
        if self.args.operation == "upgrade_check":
            if not self.args.target_version:
                raise argx.UserError("--target-version is required for this operation")
            body = {
                "task_type": self.args.operation,
                "target_version": str(self.args.target_version),
            }
        elif self.args.operation == "migration_check":
            if not self.args.source_service_uri:
                raise argx.UserError("--source-service-uri is required for this operation")
            body = {
                "task_type": self.args.operation,
                "migration_check": {"source_service_uri": self.args.source_service_uri},
            }
            if self.args.ignore_dbs:
                body["migration_check"]["ignore_dbs"] = self.args.ignore_dbs
        else:
            raise NotImplementedError(f"Operation {self.args.operation} is not implemented")

        response = self.client.create_service_task(
            project=self.get_project(),
            service=self.args.service_name,
            body=body,
        )
        self.print_response(
            [response["task"]],
            format=self.args.format,
            json=self.args.json,
            table_layout=["task_type", "success", "task_id"],
        )
        print(response["task"]["result"])

    @arg.project
    @arg.service_name
    @arg(
        "--task-id",
        help="Task id to check the status",
    )
    @arg("--format", help="Format string for output")
    @arg.json
    def service__task_get(self) -> None:
        """Get a service task"""
        response = self.client.get_service_task(
            project=self.get_project(),
            service=self.args.service_name,
            task_id=self.args.task_id,
        )
        self.print_response(
            [response],
            format=self.args.format,
            json=self.args.json,
            table_layout=["task_type", "success", "task_id", "result"],
        )

    @arg.project
    @arg.service_name
    @arg.topic
    @arg.partitions
    @arg.replication
    @arg.min_insync_replicas
    @arg.retention
    @arg.retention_ms
    @arg.retention_bytes
    @arg.remote_storage_enable
    @arg.remote_storage_disable
    @arg.local_retention_ms
    @arg.local_retention_bytes
    @arg.inkless_enable
    @arg.inkless_disable
    @arg.tag
    @arg(
        "--cleanup-policy",
        help="Topic cleanup policy",
        choices=["delete", "compact"],
        default="delete",
    )
    def service__topic_create(self) -> None:
        """Create a Kafka topic"""

        tags = list(map(parse_tag_str, self.args.topic_option_tag or []))
        tag_keys = list(map(lambda d: d.get("key"), tags))
        repeated_keys = [key for key, count in Counter(tag_keys).items() if count > 1 and key is not None]
        if len(repeated_keys) > 0:
            raise argx.UserError(f"Duplicate tags detected: {', '.join(repeated_keys)}")

        response = self.client.create_service_topic(
            project=self.get_project(),
            service=self.args.service_name,
            topic=self.args.topic,
            partitions=self.args.partitions,
            replication=self.args.replication,
            min_insync_replicas=self.args.min_insync_replicas,
            retention_bytes=self.args.retention_bytes,
            retention_hours=self.args.retention,
            retention_ms=self.args.retention_ms,
            cleanup_policy=self.args.cleanup_policy,
            remote_storage_enable=self._remote_storage_enable(),
            local_retention_ms=self.args.local_retention_ms,
            local_retention_bytes=self.args.local_retention_bytes,
            inkless_enable=self._inkless_enable(),
            tags=tags,
        )
        print(response)

    @arg.project
    @arg.service_name
    @arg.topic
    @arg.partitions
    @arg.min_insync_replicas
    @arg.retention
    @arg.retention_ms
    @arg.retention_bytes
    @arg.remote_storage_enable
    @arg.remote_storage_disable
    @arg.local_retention_ms
    @arg.local_retention_bytes
    @arg.tagupdate
    @arg.inkless_enable
    @arg.inkless_disable
    @arg.untag
    @arg("--replication", help="Replication factor", type=int, required=False)
    def service__topic_update(self) -> None:
        """Update a Kafka topic"""

        new_tags = list(map(parse_tag_str, self.args.topic_option_tag or []))
        untags = list(map(parse_untag_str, self.args.topic_option_untag or []))
        keys: list = list(map(lambda d: d.get("key"), new_tags))
        tag_keys = keys + untags
        repeated_keys = [key for key, count in Counter(tag_keys).items() if count > 1]
        if len(repeated_keys) > 0:
            raise argx.UserError(f"Duplicate tags detected: {', '.join(repeated_keys)}")

        # Merging updated tags set on the client side as API call replaces tags set
        tags = None
        if len(new_tags) + len(untags) > 0:
            topic = self.client.get_service_topic(
                project=self.get_project(), service=self.args.service_name, topic=self.args.topic
            )
            tags = topic.get("tags", [])
            tags = list(filter(lambda t: t.get("key") not in tag_keys, tags)) + new_tags

        response = self.client.update_service_topic(
            project=self.get_project(),
            service=self.args.service_name,
            topic=self.args.topic,
            min_insync_replicas=self.args.min_insync_replicas,
            partitions=self.args.partitions,
            replication=self.args.replication,
            retention_bytes=self.args.retention_bytes,
            retention_hours=self.args.retention,
            retention_ms=self.args.retention_ms,
            remote_storage_enable=self._remote_storage_enable(),
            local_retention_ms=self.args.local_retention_ms,
            local_retention_bytes=self.args.local_retention_bytes,
            inkless_enable=self._inkless_enable(),
            tags=tags,
        )
        print(response["message"])

    def _remote_storage_enable(self) -> bool | None:
        if self.args.remote_storage_enable and self.args.remote_storage_disable:
            raise argx.UserError("Only set at most one of --remote-storage-enable and --remote-storage-disable")
        if self.args.remote_storage_enable:
            return True
        elif self.args.remote_storage_disable:
            return False
        else:
            return None

    def _inkless_enable(self) -> bool | None:
        if self.args.inkless_enable and self.args.inkless_disable:
            raise argx.UserError("Only set at most one of --inkless-enable and --inkless-disable")
        if self.args.inkless_enable:
            return True
        elif self.args.inkless_disable:
            return False
        else:
            return None

    @arg.project
    @arg.service_name
    @arg.topic
    def service__topic_delete(self) -> None:
        """Delete a Kafka topic"""
        response = self.client.delete_service_topic(
            project=self.get_project(), service=self.args.service_name, topic=self.args.topic
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg(
        "--permission",
        help="Permission, one of read, write or readwrite",
        required=True,
    )
    @arg(
        "--topic",
        help="Topic name, accepts * and ? as wildcard characters",
        required=True,
    )
    @arg(
        "--username",
        help="Username, accepts * and ? as wildcard characters",
        required=True,
    )
    def service__acl_add(self) -> None:
        """Add an Aiven ACL for Kafka entry"""
        response = self.client.add_service_kafka_acl(
            project=self.get_project(),
            service=self.args.service_name,
            permission=self.args.permission,
            topic=self.args.topic,
            username=self.args.username,
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg("acl_id", help="ID of the ACL entry to delete")
    def service__acl_delete(self) -> None:
        """Delete an Aiven ACL for Kafka entry"""
        response = self.client.delete_service_kafka_acl(
            project=self.get_project(), service=self.args.service_name, acl_id=self.args.acl_id
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg.json
    def service__acl_list(self) -> None:
        """List Aiven ACL for Kafka entries"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)

        layout = ["id", "username", "topic", "permission"]

        self.print_response(service.get("acl", []), json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg(
        "--permission",
        help="Permission, schema_registry_read or schema_registry_write",
        required=True,
    )
    @arg(
        "--resource",
        help="Resource Config: or Subject:<subject>, accepts * and ? as wildcard characters",
        required=True,
    )
    @arg(
        "--username",
        help="Username, accepts * and ? as wildcard characters",
        required=True,
    )
    def service__schema_registry_acl_add(self) -> None:
        """Add a Kafka Schema Registry ACL entry"""
        response = self.client.add_service_kafka_schema_registry_acl(
            project=self.get_project(),
            service=self.args.service_name,
            permission=self.args.permission,
            resource=self.args.resource,
            username=self.args.username,
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg("acl_id", help="ID of the Schema Registry ACL entry to delete")
    def service__schema_registry_acl_delete(self) -> None:
        """Delete a Kafka Schema Registry ACL entry"""
        response = self.client.delete_service_kafka_schema_registry_acl(
            project=self.get_project(), service=self.args.service_name, acl_id=self.args.acl_id
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg.json
    def service__schema_registry_acl_list(self) -> None:
        """List Kafka Schema Registry ACL entries"""
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)

        layout = ["id", "username", "resource", "permission"]

        self.print_response(service.get("schema_registry_acl", []), json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--username", help="Only show rules for user", required=False)
    @arg.json
    def service__es_acl_list(self) -> None:
        """List Elasticsearch ACL configuration"""
        response = self.client.list_service_elasticsearch_acl_config(
            project=self.get_project(), service=self.args.service_name
        )
        acl_config = response.get("elasticsearch_acl_config", {})

        if self.args.json:
            self.print_response(acl_config, json=self.args.json)
            return

        print("ACL:         ", "enabled" if acl_config.get("enabled") else "disabled")
        print("ExtendedACL: ", "enabled" if acl_config.get("extendedAcl") else "disabled")
        print("rules:")
        for acl in acl_config.get("acls"):
            if self.args.username is not None and acl["username"] != self.args.username:
                continue
            print("    {}:".format(acl["username"]))
            for rule in acl["rules"]:
                print("          {}/{}".format(rule["index"], rule["permission"]))

    @arg.project
    @arg.service_name
    def service__es_acl_enable(self) -> None:
        """Enable Elasticsearch ACL configuration"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(), service=self.args.service_name, enabled=True
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__es_acl_extended_enable(self) -> None:
        """Enable Elasticsearch Extended ACL"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(), service=self.args.service_name, extended_acl=True
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__es_acl_disable(self) -> None:
        """Disable Elasticsearch ACL configuration"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(), service=self.args.service_name, enabled=False
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__es_acl_extended_disable(self) -> None:
        """Disable Elasticsearch Extended ACL"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(), service=self.args.service_name, extended_acl=False
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user (no wildcards)", required=True)
    @arg(
        "rule",
        nargs="+",
        help=(
            "index/permission (index accepts * and ? as wildcard characters, "
            "allowed permissions are admin,read,write,readwrite,deny)."
        ),
    )
    def service__es_acl_add(self) -> None:
        """Add rules to elastic ACL configuration"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
            add_rules=self.args.rule,
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    @arg("--username", help="Service username (no wildcards)", required=True)
    @arg(
        "rule",
        nargs="*",
        help="index rule to remove (if none given all rules are removed).",
    )
    def service__es_acl_del(self) -> None:
        """Delete rules from elastic ACL configuration"""
        response = self.client.update_service_elasticsearch_acl_config(
            project=self.get_project(),
            service=self.args.service_name,
            username=self.args.username,
            del_rules=self.args.rule,
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__opensearch__security_management__status(self) -> None:
        """Show status of the opensearch security"""
        response = self.client.opensearch_security_get(
            project=self.get_project(),
            service=self.args.service_name,
        )
        available = response.get("security_plugin_available", False)
        admin_enabled = response.get("security_plugin_admin_enabled", False)
        message = response.get("message")
        if not available:
            if not message:
                print("Opensearch Security is not available for the service")
                return
            print(message)
            return
        if admin_enabled:
            print("Opensearch Security Management enabled")
            return
        print("Opensearch Security Management disabled")

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__status(self) -> None:
        """Deprecated: Show status of the opensearch security"""
        print("Deprected: `use service opensearch security-management status` instead")
        self.service__opensearch__security_management__status()

    @arg.project
    @arg.service_name
    def service__opensearch__security_management__set(self) -> None:
        """Set the password for the opensearch security management"""
        print("Opensearch Security Management is enabled by setting the password")
        print("for the security management user. Once enabled normal Aiven service")
        print("user and ACL management is no longer used and all user and access control")
        print("can only be done using the native Opensearch Security API or dashboard.")
        if self.confirm("this action is unrevertable. Proceed (y/N)? "):
            passwd = self.enter_password(
                prompt="Setup Opensearch Security Manager",
                var="AIVEN_OS_SECOP_PASSWORD",
                confirm=True,
            )
            response = self.client.opensearch_security_set(
                project=self.get_project(),
                service=self.args.service_name,
                password=passwd,
            )
            print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__set(self) -> None:
        """Deprecated: Set the password for the opensearch security management"""
        print("Deprected: `use service opensearch security-management set` instead")
        self.service__opensearch__security_management__set()

    @arg.project
    @arg.service_name
    def service__opensearch__security_management__reset(self) -> None:
        """Reset the password for the opensearch security management"""
        old_passwd = self.enter_password(
            prompt="Old Opensearch Security Manager password",
            var="AIVEN_OS_SECOP_PASSWORD",
        )
        new_passwd = self.enter_password(
            prompt="New password",
            var="AIVEN_OS_SECOP_NEW_PASSWORD",
            confirm=True,
        )
        response = self.client.opensearch_security_reset(
            project=self.get_project(),
            service=self.args.service_name,
            old_password=old_passwd,
            new_password=new_passwd,
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__reset(self) -> None:
        """Deprecated: Reset the password for the opensearch security management"""
        print("Deprected: `use service opensearch security-management reset` instead")
        self.service__opensearch__security_management__reset()

    @arg.project
    @arg.service_name
    def service__connector__available(self) -> None:
        """List available Kafka connectors"""
        project_name = self.get_project()
        self.print_response(self.client.get_available_kafka_connectors(project_name, self.args.service_name))

    @arg.project
    @arg.service_name
    def service__connector__list(self) -> None:
        """List Kafka connectors"""
        project_name = self.get_project()
        self.print_response(self.client.list_kafka_connectors(project_name, self.args.service_name))

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__status(self) -> None:
        """Get Kafka connector status"""
        project_name = self.get_project()
        self.print_response(
            self.client.get_kafka_connector_status(project_name, self.args.service_name, self.args.connector)
        )

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__schema(self) -> None:
        """Get Kafka connector schema"""
        project_name = self.get_project()
        self.print_response(
            self.client.get_kafka_connector_schema(project_name, self.args.service_name, self.args.connector)
        )

    @arg.project
    @arg.service_name
    @arg.json_path_or_string("connector_config")
    def service__connector__create(self) -> None:
        """Create a Kafka connector"""
        project_name = self.get_project()
        self.client.create_kafka_connector(project_name, self.args.service_name, self.args.connector_config)

    @arg.project
    @arg.service_name
    @arg.connector_name
    @arg(
        "--fetch-current",
        action="store_true",
        help="Fetch current config first, and use as a base for update",
    )
    @arg.json_path_or_string("connector_config")
    def service__connector__update(self) -> None:
        """Update a Kafka connector"""
        project_name = self.get_project()
        self.client.update_kafka_connector(
            project_name,
            self.args.service_name,
            self.args.connector,
            self.args.connector_config,
            self.args.fetch_current,
        )

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__delete(self) -> None:
        """Delete a Kafka connector"""
        project_name = self.get_project()
        self.client.delete_kafka_connector(project_name, self.args.service_name, self.args.connector)

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__pause(self) -> None:
        """Pause a Kafka connector"""
        project_name = self.get_project()
        self.client.pause_kafka_connector(project_name, self.args.service_name, self.args.connector)

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__resume(self) -> None:
        """Resume a Kafka connector"""
        project_name = self.get_project()
        self.client.resume_kafka_connector(project_name, self.args.service_name, self.args.connector)

    @arg.project
    @arg.service_name
    @arg.connector_name
    def service__connector__restart(self) -> None:
        """Restart a Kafka connector"""
        project_name = self.get_project()
        self.client.restart_kafka_connector(project_name, self.args.service_name, self.args.connector)

    @arg.project
    @arg.service_name
    @arg.connector_name
    @arg("task", help="Task id")
    def service__connector__restart_task(self) -> None:
        """Restart a Kafka connector task"""
        project_name = self.get_project()
        self.client.restart_kafka_connector_task(project_name, self.args.service_name, self.args.connector, self.args.task)

    @arg.project
    @arg.service_name
    @arg("--schema-id", required=True, help="Schema ID")
    def service__schema__get(self) -> None:
        """Get Kafka Schema Registry schema"""
        project_name = self.get_project()
        schema = self.client.get_schema(project_name, self.args.service_name, self.args.schema_id)
        self.print_response(schema)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.schema
    def service__schema__create(self) -> None:
        """Create Kafka Schema Registry schema"""
        project_name = self.get_project()
        schema = self.client.create_schema_subject_version(
            project_name, self.args.service_name, self.args.subject, self.args.schema
        )
        self.print_response(schema)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.version_id
    @arg.schema
    def service__schema__check(self) -> None:
        """Check Kafka Schema Registry schema compatibility"""
        project_name = self.get_project()
        schema = self.client.check_schema_compatibility(
            project_name,
            self.args.service_name,
            self.args.subject,
            self.args.version_id,
            self.args.schema,
        )
        self.print_response(schema)

    @arg.project
    @arg.service_name
    def service__schema__configuration(self) -> None:
        """Get Kafka Schema Registry global configuration"""
        project_name = self.get_project()
        self.print_response(self.client.get_schema_global_configuration(project_name, self.args.service_name))

    @arg.project
    @arg.service_name
    @arg.compatibility
    def service__schema__configuration_update(self) -> None:
        """Update Kafka Schema Registry global configuration"""
        project_name = self.get_project()
        self.client.update_schema_global_configuration(project_name, self.args.service_name, self.args.compatibility)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.compatibility
    def service__schema__subject_update(self) -> None:
        """Update Kafka Schema Registry subject"""
        project_name = self.get_project()
        self.client.update_schema_subject_configuration(
            project_name, self.args.service_name, self.args.subject, self.args.compatibility
        )

    @arg.project
    @arg.service_name
    @arg.subject
    def service__schema__subject_configuration(self) -> None:
        """Update Kafka Schema Registry subject"""
        project_name = self.get_project()
        response = self.client.get_schema_subject_configuration(project_name, self.args.service_name, self.args.subject)
        self.print_response(response)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.compatibility
    def service__schema__subject_configuration_update(self) -> None:
        """Update Kafka Schema Registry global configuration"""
        project_name = self.get_project()
        self.client.update_schema_subject_configuration(
            project_name, self.args.service_name, self.args.subject, self.args.compatibility
        )

    @arg.project
    @arg.service_name
    def service__schema__subject_list(self) -> None:
        """List Kafka Schema Registry subjects"""
        project_name = self.get_project()
        self.print_response(self.client.list_schema_subjects(project_name, self.args.service_name))

    @arg.project
    @arg.service_name
    @arg.subject
    def service__schema__subject_delete(self) -> None:
        """Delete Kafka Schema Registry subject"""
        project_name = self.get_project()
        self.client.delete_schema_subject(project_name, self.args.service_name, self.args.subject)

    @arg.project
    @arg.service_name
    @arg.subject
    def service__schema__subject_version__list(self) -> None:
        """List or get Kafka Schema Registry subject version"""
        project_name = self.get_project()
        response = self.client.list_schema_subject_versions(project_name, self.args.service_name, self.args.subject)
        self.print_response(response)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.version_id
    def service__schema__subject_version__get(self) -> None:
        """Get Kafka Schema Registry subject version"""
        project_name = self.get_project()
        response = self.client.get_schema_subject_version(
            project_name, self.args.service_name, self.args.subject, self.args.version_id
        )
        self.print_response(response["version"])

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.version_id
    def service__schema__subject_version__schema(self) -> None:
        """Get Kafka Schema Registry subject schema"""
        project_name = self.get_project()
        response = self.client.get_schema_subject_version_schema(
            project_name, self.args.service_name, self.args.subject, self.args.version_id
        )
        self.print_response(response)

    @arg.project
    @arg.service_name
    @arg.subject
    @arg.version_id
    def service__schema__subject_version__delete(self) -> None:
        """Delete Kafka Schema Registry subject version"""
        project_name = self.get_project()
        self.client.delete_schema_subject_version(
            project_name, self.args.service_name, self.args.subject, self.args.version_id
        )

    @arg.project
    @arg.service_name
    def mirrormaker__replication_flow__list(self) -> None:
        """List Kafka MirrorMaker replication flows"""
        project_name = self.get_project()
        self.print_response(self.client.list_mirrormaker_replication_flows(project_name, self.args.service_name))

    @arg.project
    @arg.service_name
    @arg.source_cluster
    @arg.target_cluster
    @arg.json_path_or_string("replication_flow_config")
    def mirrormaker__replication_flow__create(self) -> None:
        """Create a Kafka MirrorMaker replication flow"""
        project_name = self.get_project()
        self.client.create_mirrormaker_replication_flow(
            project_name,
            self.args.service_name,
            self.args.source_cluster,
            self.args.target_cluster,
            self.args.replication_flow_config,
        )

    @arg.project
    @arg.service_name
    @arg.source_cluster
    @arg.target_cluster
    @arg.json_path_or_string("replication_flow_config")
    def mirrormaker__replication_flow__update(self) -> None:
        """Update a Kafka MirrorMaker replication flow"""
        project_name = self.get_project()
        self.print_response(
            self.client.update_mirrormaker_replication_flow(
                project_name,
                self.args.service_name,
                self.args.source_cluster,
                self.args.target_cluster,
                self.args.replication_flow_config,
            )
        )

    @arg.project
    @arg.service_name
    @arg.source_cluster
    @arg.target_cluster
    def mirrormaker__replication_flow__get(self) -> None:
        """Get a Kafka MirrorMaker replication flow"""
        project_name = self.get_project()
        self.print_response(
            self.client.get_mirrormaker_replication_flow(
                project_name,
                self.args.service_name,
                self.args.source_cluster,
                self.args.target_cluster,
            )
        )

    @arg.project
    @arg.service_name
    @arg.source_cluster
    @arg.target_cluster
    def mirrormaker__replication_flow__delete(self) -> None:
        """Delete a Kafka MirrorMaker replication flow"""
        project_name = self.get_project()
        self.client.delete_mirrormaker_replication_flow(
            project_name,
            self.args.service_name,
            self.args.source_cluster,
            self.args.target_cluster,
        )

    @arg.project
    @arg("service", nargs="+", help="Service to wait for")
    @arg.timeout
    def service__wait(self) -> int | None:
        """Wait service to reach the 'RUNNING' state"""
        start_time = time.time()
        report_interval = 30.0
        next_report = start_time + report_interval
        last: dict = {}
        while True:
            all_running = True
            for service in self.args.service:
                info = self.client.get_service(project=self.get_project(), service=service)
                if info["state"] != last.get(service):
                    self.log.info("Service %r state is now %r", service, info["state"])
                last[service] = info["state"]
                if info["state"] != "RUNNING":
                    all_running = False

            if all_running:
                self.log.info("Service(s) RUNNING: %s", ", ".join(self.args.service))
                return 0

            if self.args.timeout is not None and (time.time() - start_time) > self.args.timeout:
                self.log.error("Timeout waiting for service(s) to start")
                return 1

            if time.time() >= next_report:
                next_report = time.time() + report_interval
                self.log.info("Waiting for services to start")

            time.sleep(3.0)

    @arg.project
    @arg.force
    @arg("service_name", help="Service name", nargs="+")
    def service__terminate(self) -> None:
        """Terminate service"""
        if not self.args.force and os.environ.get("AIVEN_FORCE") != "true":
            self.print_boxed(
                [
                    "Please re-enter the service name(s) to confirm the service termination.",
                    "This cannot be undone and all the data in the service will be lost!",
                    "Re-entering service name(s) can be skipped with the --force option.",
                ]
            )

            for name in self.args.service_name:
                user_input = input("Re-enter service name {!r} for immediate termination: ".format(name))
                if user_input != name:
                    raise argx.UserError("Not confirmed by user. Aborting termination.")

        for name in self.args.service_name:
            self.client.delete_service(project=self.get_project(), service=name)
            self.log.info("%s: terminated", name)

    @arg.project
    @arg.json
    @arg.verbose
    def vpc__list(self) -> None:
        """List VPCs for a project"""
        project_name = self.get_project()
        try:
            vpc_list = self.client.list_project_vpcs(project=project_name)["vpcs"]
            layout = ["project_vpc_id", "cloud_name", "network_cidr", "state"]
            if self.args.verbose:
                layout += ["create_time", "update_time"]
            self.print_response(vpc_list, json=self.args.json, table_layout=layout)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project VPC listing for '{}' failed".format(project_name))

    def _vpc_create(self) -> None:
        """Helper method for vpc__create and vpc__request"""
        project_name = self.get_project()
        try:
            vpc = self.client.create_project_vpc(
                project=project_name,
                cloud=self.args.cloud,
                network_cidr=self.args.network_cidr,
                peering_connections=[],
            )
            layout = ["project_vpc_id", "state", "cloud_name", "network_cidr"]
            self.print_response(vpc, json=self.args.json, table_layout=layout, single_item=True)
        except client.Error as ex:
            print(ex.response.text)
            raise

    @arg.project
    @arg.json
    @arg.cloud
    @arg(
        "--network-cidr",
        help="The network range in the Aiven project VPC in CIDR format (a.b.c.d/e)",
        required=True,
    )
    def vpc__create(self) -> None:
        """Create a VPC for a project"""
        return self._vpc_create()

    @arg.project
    @arg.json
    @arg.cloud
    @arg(
        "--network-cidr",
        help="The network range in the Aiven project VPC in CIDR format (a.b.c.d/e)",
        required=True,
    )
    def vpc__request(self) -> None:
        """Request a VPC for a project (Deprecated: use vpc create)"""
        self.log.warning("'vpc request' is going to be deprecated. Use the 'vpc create' command instead.")
        return self._vpc_create()

    _project_vpc_id_help = "Aiven project VPC ID. See 'vpc list'"

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    def vpc__delete(self) -> None:
        """Delete a project VPC"""
        project_name = self.get_project()
        try:
            vpc = self.client.delete_project_vpc(
                project=project_name,
                project_vpc_id=self.args.project_vpc_id,
            )
            layout = ["project_vpc_id", "state", "cloud_name", "network_cidr"]
            self.print_response(vpc, json=self.args.json, table_layout=layout, single_item=True)
        except client.Error as ex:
            print(ex.response.text)
            raise

    @arg.project
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg.json
    @arg.verbose
    def vpc__peering_connection__list(self) -> None:
        """List VPC peering connections for a project"""
        project_name = self.get_project()
        try:
            peering_connections = self.client.get_project_vpc(
                project=project_name,
                project_vpc_id=self.args.project_vpc_id,
            )["peering_connections"]
            layout = [
                "peer_cloud_account",
                "peer_resource_group",
                "peer_vpc",
                "peer_region",
                "state",
            ]
            if self.args.verbose:
                layout += ["create_time", "update_time"]
            self.print_response(
                [dict(pcx, peer_resource_group=pcx.get("peer_resource_group")) for pcx in peering_connections],
                json=self.args.json,
                table_layout=layout,
            )
        except client.Error as ex:
            print(ex.response.text)
            msg = "Peering connection listing for VPC '{}' of project '{}' failed".format(
                self.args.project_vpc_id,
                project_name,
            )
            raise argx.UserError(msg)

    _peer_cloud_account_help = "AWS account ID, Google project ID, or Azure subscription ID"
    _peer_resource_group_help = "Azure resource group name"
    _peer_vpc_help = "AWS VPC ID, Google VPC network name, or Azure VNet name"
    _peer_region_help = "AWS region of peer VPC, if other than the region of the Aiven project VPC"

    @arg.project
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg(
        "--peer-resource-group",
        help=_peer_resource_group_help,
        default=UNDEFINED,
    )
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    @arg.json
    @arg.verbose
    def vpc__peering_connection__get(self) -> None:
        """Show details of a VPC peering connection"""
        project_name = self.get_project()
        try:
            try:
                peering_connection = self.client.get_project_vpc_peering_connection(
                    project=project_name,
                    project_vpc_id=self.args.project_vpc_id,
                    peer_cloud_account=self.args.peer_cloud_account,
                    peer_resource_group=self.args.peer_resource_group,
                    peer_vpc=self.args.peer_vpc,
                )
            except KeyError as ex:
                raise argx.UserError("Peering connection does not exist") from ex
            if self.args.json:
                print(jsonlib.dumps(peering_connection, indent=4, sort_keys=True))
            else:
                print("State: {}".format(peering_connection["state"]))
                user_peer_network_cidrs = peering_connection.get("user_peer_network_cidrs", [])
                if user_peer_network_cidrs:
                    print("User-defined peer network cidrs: {}".format(", ".join(user_peer_network_cidrs)))
                state_info = peering_connection["state_info"]
                if state_info is not None:
                    print("Message: {}\n".format(state_info.pop("message")))
                    if state_info:
                        self.print_response(state_info, json=False, single_item=True)
        except client.Error as ex:
            print(ex.response.text)
            msg = "Peering connection listing for VPC '{}' of project '{}' failed".format(
                self.args.project_vpc_id,
                project_name,
            )
            raise argx.UserError(msg)

    def _vpc_peering_connection_create(
        self,
        peer_region: str | None,
        peer_resource_group: str | None,
        peer_azure_app_id: str | None,
        peer_azure_tenant_id: str | None,
        user_peer_network_cidrs: Sequence[str] | None,
    ) -> None:
        """Helper method for vpc__peering_connection__create and vpc__peering_connection__request"""
        project_name = self.get_project()
        try:
            vpc_peering_connection = self.client.create_project_vpc_peering_connection(
                project=project_name,
                project_vpc_id=self.args.project_vpc_id,
                peer_cloud_account=self.args.peer_cloud_account,
                peer_vpc=self.args.peer_vpc,
                peer_region=peer_region,
                peer_resource_group=peer_resource_group,
                peer_azure_app_id=peer_azure_app_id,
                peer_azure_tenant_id=peer_azure_tenant_id,
                user_peer_network_cidrs=user_peer_network_cidrs,
            )
            self.print_response(vpc_peering_connection, json=self.args.json, single_item=True)
        except client.Error as ex:
            print(ex.response.text)
            raise

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    @arg("--peer-region", help=_peer_region_help)
    @arg("--peer-resource-group", help=_peer_resource_group_help)
    @arg("--peer-azure-app-id", help="Azure app object ID")
    @arg("--peer-azure-tenant-id", help="Azure AD tenant ID")
    @arg(
        "--user-peer-network-cidr",
        help="User-defined peer network IP range for routing/firewall",
        action="append",
        dest="user_peer_network_cidrs",
    )
    def vpc__peering_connection__create(self) -> None:
        """Create a peering connection for a project VPC"""
        return self._vpc_peering_connection_create(
            peer_region=self.args.peer_region,
            peer_resource_group=self.args.peer_resource_group,
            peer_azure_app_id=self.args.peer_azure_app_id,
            peer_azure_tenant_id=self.args.peer_azure_tenant_id,
            user_peer_network_cidrs=self.args.user_peer_network_cidrs,
        )

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    def vpc__peering_connection__request(self) -> None:
        """Request a peering connection for a project VPC (Deprecated: use vpc peering-connection create)"""
        self.log.warning(
            "'vpc peering-connection request' is going to be deprecated. Use the 'vpc peering-connection create' command "
            "instead."
        )
        return self._vpc_peering_connection_create(
            peer_region=None,
            peer_resource_group=None,
            peer_azure_app_id=None,
            peer_azure_tenant_id=None,
            user_peer_network_cidrs=None,
        )

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg(
        "--peer-resource-group",
        required=False,
        help=_peer_resource_group_help,
        default=UNDEFINED,
    )
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    @arg("--peer-region", help=_peer_region_help)
    def vpc__peering_connection__delete(self) -> None:
        """Delete a peering connection for a project VPC"""
        project_name = self.get_project()
        try:
            vpc_peering_connection = self.client.delete_project_vpc_peering_connection(
                project=project_name,
                project_vpc_id=self.args.project_vpc_id,
                peer_cloud_account=self.args.peer_cloud_account,
                peer_resource_group=self.args.peer_resource_group,
                peer_vpc=self.args.peer_vpc,
                peer_region=self.args.peer_region,
            )
            self.print_response(vpc_peering_connection, json=self.args.json, single_item=True)
        except client.Error as ex:
            print(ex.response.text)
            raise

    def _validate_using_cloud_vpc(self) -> None:
        """Raise an error if we might unexpectedly end up using a Project VPC"""
        # If the user was specific about VPC then we don't need to worry
        if self.args.no_project_vpc or self.args.project_vpc_id is not None:
            return

        # If the user did not specify a cloud, then `service create` will use
        # some variant of something historical, and `service update` will use
        # the same cloud. In either case, we don't need to worry.
        if self.args.cloud is None:
            return

        project_name = self.get_project()
        vpc_list = self.client.list_project_vpcs(project=project_name)["vpcs"]
        clouds_with_vpc = [x["cloud_name"] for x in vpc_list]
        if self.args.cloud in clouds_with_vpc:
            raise argx.UserError(
                f"Cloud {self.args.cloud} has a VPC. Specify --project-vpc-id=<vpc-id> to use it,"
                " or --no-project-vpc to use the public internet"
            )

    def _get_service_project_vpc_id(self) -> object | str | None:
        """Utility method for service_create and service_update"""
        if self.args.project_vpc_id is None:
            self._validate_using_cloud_vpc()
            project_vpc_id = None if self.args.no_project_vpc else UNDEFINED
        elif self.args.no_project_vpc:
            raise argx.UserError("Only one of --project-vpc-id and --no-project-vpc can be specified")
        else:
            project_vpc_id = self.args.project_vpc_id
        return project_vpc_id

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg("--peer-resource-group", help=_peer_resource_group_help)
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    @arg("cidrs", nargs="+", metavar="CIDR")
    def vpc__user_peer_network_cidr__add(self) -> None:
        """Add one ore more peer network CIDRs to a VPC"""
        project_name = self.get_project()
        add_base = {
            "peer_cloud_account": self.args.peer_cloud_account,
            "peer_vpc": self.args.peer_vpc,
        }
        if self.args.peer_resource_group is not None:
            add_base["peer_resource_group"] = self.args.peer_resource_group
        add = [dict(add_base, cidr=cidr) for cidr in self.args.cidrs]
        self.client.update_project_vpc_user_peer_network_cidrs(
            project=project_name,
            project_vpc_id=self.args.project_vpc_id,
            add=add,
        )

    @arg.project
    @arg.json
    @arg("--project-vpc-id", required=True, help=_project_vpc_id_help)
    @arg("cidrs", nargs="+", metavar="CIDR")
    def vpc__user_peer_network_cidr__delete(self) -> None:
        """Delete one ore more peer network CIDRs to a VPC"""
        project_name = self.get_project()
        self.client.update_project_vpc_user_peer_network_cidrs(
            project=project_name,
            project_vpc_id=self.args.project_vpc_id,
            delete=self.args.cidrs,
        )

    def _get_service_type(self) -> str:
        return self.args.service_type.partition(":")[0]

    def _get_plan(self) -> str:
        maybe_plan = self.args.service_type.partition(":")[2]
        if maybe_plan:
            return maybe_plan
        elif self.args.plan:
            return self.args.plan
        raise argx.UserError("No subscription plan given")

    @arg.project
    @arg.service_name
    @arg("--group-name", help="service group (deprecated)")
    @arg(
        "-t",
        "--service-type",
        help="type of service (see 'service types')",
        required=True,
    )
    @arg("-p", "--plan", help="subscription plan of service", required=False)
    @arg.disk_space_mb
    @arg.cloud
    @arg(
        "--no-fail-if-exists",
        action="store_true",
        default=False,
        help="do not fail if service already exists",
    )
    @arg.user_config
    @arg(
        "--project-vpc-id",
        help="Put service into a project VPC. The VPC's cloud must match the service's cloud",
    )
    @arg(
        "--no-project-vpc",
        action="store_true",
        help="Do not put the service into a project VPC even if the project has one in the selected cloud",
    )
    @arg(
        "--static-ip",
        action="append",
        help="Associate static IP address with service",
        metavar="STATIC_IP_ID",
        dest="static_ips",
    )
    @arg(
        "--read-replica-for",
        help="Creates a read replica for given source service. Only applicable for certain service types",
    )
    @arg(
        "--enable-termination-protection",
        action="store_true",
        default=False,
        help="Enable termination protection",
    )
    @arg("--service-to-fork-from", help="Service to fork from")
    @arg("--recovery-target-time", help="PITR recovery point in format 2023-02-01 11:38:49")
    @arg.force
    def service__create(self) -> None:
        """Create a service"""
        service_type = self._get_service_type()
        plan = self._get_plan()
        if self.args.group_name:
            self.log.warning("--group-name parameter is deprecated and has no effect")

        project_vpc_id = self._get_service_project_vpc_id()
        project = self.get_project()
        user_config_schema = self._get_service_type_user_config_schema(project=project, service_type=service_type)
        user_config = self.create_user_config(user_config_schema)

        # If the user requests a specific version, check EOL status
        requested_version = self._extract_user_config_version(service_type, user_config)

        if requested_version:
            self._do_version_eol_check(service_type, requested_version, project=project)

        service_integrations = []

        if self.args.read_replica_for:
            if self.args.service_type == "pg":
                user_config["pg_read_replica"] = True
                user_config["service_to_fork_from"] = self.args.read_replica_for
            else:
                service_integrations.append(
                    {
                        "integration_type": "read_replica",
                        "source_service": self.args.read_replica_for,
                    }
                )
        elif self.args.recovery_target_time and self.args.service_to_fork_from:
            user_config["service_to_fork_from"] = self.args.service_to_fork_from
            user_config["recovery_target_time"] = self.args.recovery_target_time
        elif self.args.service_to_fork_from:
            user_config["service_to_fork_from"] = self.args.service_to_fork_from

        try:
            self.client.create_service(
                project=project,
                service=self.args.service_name,
                service_type=service_type,
                plan=plan,
                disk_space_mb=self.args.disk_space_mb,
                cloud=self.args.cloud,
                user_config=user_config,
                project_vpc_id=project_vpc_id,
                termination_protection=self.args.enable_termination_protection,
                service_integrations=service_integrations,
                static_ips=self.args.static_ips or (),
            )
        except client.Error as ex:
            print(ex.response)
            if not self.args.no_fail_if_exists or ex.response.status_code != HTTPStatus.CONFLICT:
                raise

            self.log.info("service '%s/%s' already exists", project, self.args.service_name)

    def _get_powered(self) -> bool | None:
        if self.args.power_on and self.args.power_off:
            raise argx.UserError("Only one of --power-on or --power-off can be specified")
        elif self.args.power_on:
            return True
        elif self.args.power_off:
            return False
        else:
            return None

    @staticmethod
    def _get_unknown_option_error(option_type: str, options: Mapping[str, Any], option: str) -> str:
        suggestion = suggest(option, options)
        if suggestion is not None:
            did_you_mean = ", did you mean: {}".format(suggestion)
        else:
            did_you_mean = ""
        return "Unknown {} {!r}{} (available options: {})".format(option_type, option, did_you_mean, ", ".join(options))

    def _get_service_type_user_config_schema(self, project: str, service_type: str) -> Mapping[str, Any]:
        service_types = self.client.get_service_types(project=project)
        try:
            service_def = service_types[service_type]
        except KeyError as ex:
            raise argx.UserError(
                self._get_unknown_option_error(
                    option_type="service type",
                    options=service_types,
                    option=service_type,
                )
            ) from ex

        return service_def["user_config_schema"]

    def _get_service_versions(self, project: str | None = None) -> Sequence[Mapping[str, Any]]:
        account_id = None
        if project:
            project_data = self.client.get_project(project=project)
            account_id = project_data["account_id"]

        return self.client.get_service_versions(account_id=account_id)

    def _get_service_version_info(self, service_type: str, version: str, project: str | None = None) -> Mapping[str, Any]:
        service_versions = self._get_service_versions(project=project)

        for service_version in service_versions:
            if service_version["service_type"] == service_type and service_version["major_version"] == version:
                return service_version

        # No match was found
        raise argx.UserError(f"{service_type} v{version} is not available")

    def _extract_user_config_version(self, service_type: str, user_config: dict) -> str | None:
        """Extracts version specified in the user config.

        This handles the special case for M3 components which also accept
        an 'm3_version' entry instead of '{service_type}_version'. If the
        user supplies an 'm3_version' this method modifies the user_config
        as the server side would.
        """
        service_version_key = f"{service_type}_version"

        # M3 components have special cases for m3_version as key
        if service_type in {"m3db", "m3aggregator", "m3coordinator"}:
            if "m3_version" in user_config:
                if service_version_key in user_config:
                    raise argx.UserError(f"'{service_version_key}' and 'm3_version' cannot be specified together")

                # Replace m3_version with service_type specific key
                user_config[service_version_key] = user_config.pop("m3_version")

        return user_config.get(service_version_key)

    def _do_version_eol_check(self, service_type: str, requested_version: str, project: str | None = None) -> None:
        """Checks the specified service version against EOL times."""
        service_version = self._get_service_version_info(service_type, requested_version, project=project)
        current_time = get_current_date()

        if not service_version["aiven_end_of_life_time"]:
            return  # No EOL specified

        end_of_life_time = parse_iso8601(service_version["aiven_end_of_life_time"])
        eol_status = "is reaching EOL soon" if current_time < end_of_life_time else "has reached EOL"

        warning = [
            "   !!! WARNING !!!",
            "",
            f"{service_type} v{requested_version} {eol_status} ({end_of_life_time.date()}).",
            "",
            "It is highly recommended to deploy newer, supported versions of the service.",
        ]

        if current_time > (end_of_life_time - EOL_ADVANCE_WARNING_TIME):
            self.print_boxed(warning)

            if not self.confirm("continue anyway (y/N)? "):
                raise argx.UserError("Aborted")

    def _get_endpoint_user_config_schema(self, project: str, endpoint_type_name: str) -> Mapping[str, Any]:
        endpoint_types_list = self.client.get_service_integration_endpoint_types(project=project)
        endpoint_types = {item["endpoint_type"]: item for item in endpoint_types_list}
        try:
            return endpoint_types[endpoint_type_name]["user_config_schema"]
        except KeyError as ex:
            raise argx.UserError(
                self._get_unknown_option_error(
                    option_type="endpoint type",
                    options=endpoint_types,
                    option=endpoint_type_name,
                )
            ) from ex

    def _get_integration_user_config_schema(self, project: str, integration_type_name: str) -> Mapping[str, Any]:
        integration_types_list = self.client.get_service_integration_types(project=project)
        integration_types = {item["integration_type"]: item for item in integration_types_list}
        try:
            return integration_types[integration_type_name]["user_config_schema"]
        except KeyError as ex:
            raise argx.UserError(
                self._get_unknown_option_error(
                    option_type="integration type",
                    options=integration_types,
                    option=integration_type_name,
                )
            ) from ex

    def _get_maintainance(self) -> Mapping[str, str] | None:
        maintenance = {}
        if self.args.maintenance_dow:
            maintenance["dow"] = self.args.maintenance_dow
        if self.args.maintenance_time:
            maintenance["time"] = self.args.maintenance_time
        return maintenance or None

    @arg.project
    @arg.service_name
    @arg("--group-name", help="New service group (deprecated)")
    @arg.cloud
    @arg.user_config
    @arg.user_option_remove
    @arg("-p", "--plan", help="subscription plan of service", required=False)
    @arg.disk_space_mb
    @arg("--power-on", action="store_true", default=False, help="Power-on the service")
    @arg(
        "--power-off",
        action="store_true",
        default=False,
        help="Temporarily power-off the service",
    )
    @arg(
        "--maintenance-dow",
        help="Set automatic maintenance window's day of week",
        choices=[
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
            "never",
        ],
    )
    @arg(
        "--maintenance-time",
        help="Set automatic maintenance window's start time (HH:MM:SS)",
    )
    @arg(
        "--use-karapace",
        action="store_true",
        default=None,
        help="Use Karapace for Schema Registry and Kafka REST API",
    )
    @arg(
        "--enable-termination-protection",
        action="store_true",
        help="Enable termination protection",
    )
    @arg(
        "--disable-termination-protection",
        action="store_true",
        help="Disable termination protection",
    )
    @arg(
        "--enable-schema-registry-authorization",
        action="store_true",
        help="Enable Schema Registry authorization",
    )
    @arg(
        "--disable-schema-registry-authorization",
        action="store_true",
        help="Disable Schema Registry authorization",
    )
    @arg(
        "--project-vpc-id",
        help="Put service into a project VPC. The VPC's cloud must match the service's cloud",
    )
    @arg(
        "--no-project-vpc",
        action="store_true",
        help="Do not put the service into a project VPC even if the project has one in the selected cloud",
    )
    @arg.force
    def service__update(self) -> None:
        """Update service settings"""
        powered = self._get_powered()
        karapace = self.args.use_karapace
        project = self.get_project()
        service = self.client.get_service(project=project, service=self.args.service_name)
        plan = self.args.plan or service["plan"]
        user_config_schema = self._get_service_type_user_config_schema(project=project, service_type=service["service_type"])
        user_config = self.create_user_config(user_config_schema)
        # If the user requests a version change, check EOL status
        service_type = service["service_type"]
        requested_version = self._extract_user_config_version(service_type, user_config)

        if requested_version:
            self._do_version_eol_check(service_type, requested_version, project=project)

        maintenance = self._get_maintainance()
        project_vpc_id = self._get_service_project_vpc_id()
        termination_protection = None
        if self.args.enable_termination_protection and self.args.disable_termination_protection:
            raise argx.UserError(
                "--enable-termination-protection and --disable-termination-protection are mutually exclusive."
            )
        if self.args.enable_termination_protection:
            termination_protection = True
        elif self.args.disable_termination_protection:
            termination_protection = False
        if self.args.group_name:
            self.log.warning("--group-name parameter is deprecated and has no effect")

        if self.args.enable_schema_registry_authorization and self.args.disable_schema_registry_authorization:
            raise argx.UserError(
                "--enable-schema-registry-authorization and --disable-schema-registry-authorization are mutually exclusive."
            )
        schema_registry_authorization = None
        if self.args.enable_schema_registry_authorization:
            schema_registry_authorization = True
        if self.args.disable_schema_registry_authorization:
            schema_registry_authorization = False

        try:
            self.client.update_service(
                cloud=self.args.cloud,
                maintenance=maintenance,
                plan=plan,
                disk_space_mb=self.args.disk_space_mb,
                karapace=karapace,
                powered=powered,
                project=project,
                service=self.args.service_name,
                user_config=user_config,
                termination_protection=termination_protection,
                project_vpc_id=project_vpc_id,
                schema_registry_authorization=schema_registry_authorization,
            )
        except client.Error as ex:
            try:
                error_message = ex.response.json()["message"]
            except ValueError:
                error_message = ex.response.text
            raise argx.UserError("Service '{}/{}' update failed: {}".format(project, self.args.service_name, error_message))

    @arg("project_name", help="Project name")
    @arg.cloud
    def project__switch(self) -> None:
        """Switch the default project"""
        projects = self.client.get_projects()
        project_names = [p["project_name"] for p in projects]
        if self.args.project_name in project_names:
            self.config["default_project"] = self.args.project_name
            self.config.save()
            self.log.info("Set project %r as the default project", self.args.project_name)
        else:
            raise argx.UserError(
                "Project {!r} does not exist, available projects: {}".format(
                    self.args.project_name, ", ".join(project_names)
                )
            )

    @arg("project_name", help="Project name")
    @arg.cloud
    def project__delete(self) -> None:
        """Delete a project"""
        self.client.delete_project(project=self.args.project_name)

    @classmethod
    def _format_card_info(cls, project: Mapping[str, Any]) -> str:
        card_info = project.get("card_info")
        if not card_info:
            return "N/A"

        return "{}/{}".format(project["card_info"]["user_email"], project["card_info"]["card_id"])

    def _show_projects(self, projects: Sequence[dict[str, Any]], verbose: bool = True) -> None:
        for project in projects:
            project["credit_card"] = self._format_card_info(project)
        if verbose:
            layout: list = [
                ["project_name", "default_cloud", "billing_currency", "vat_id"],
                "credit_card",
                "billing_address",
                "country_code",
            ]
            if any(project["billing_extra_text"] for project in projects):
                layout.append("billing_extra_text")
        else:
            layout = [["project_name", "default_cloud", "credit_card"]]
        self.print_response(projects, json=getattr(self.args, "json", False), table_layout=layout)

    def _resolve_parent_id(self, parent_id: str) -> str:
        """Resolves parent id to an account id, if parent id was an organization id"""

        if parent_id.startswith("org"):
            org_info = self.client.get_organization(parent_id)
            return org_info["account_id"]
        return parent_id

    @arg("project_name", help="Project name")
    @arg("--billing-group-id", help="Billing group ID of the project")
    @arg.cloud
    @arg(
        "--no-fail-if-exists",
        action="store_true",
        default=False,
        help="Do not fail if project already exists",
    )
    @arg(
        "-c",
        "--copy-from-project",
        metavar="PROJECT",
        help="Copy project settings from an existing project",
    )
    @arg(
        "--use-source-project-billing-group",
        action="store_true",
        default=False,
        help=(
            "If copying from existing project, use the same billing group "
            "used by source project instead of creating a new one"
        ),
    )
    @arg.tech_email
    @arg.parent_id_mandatory
    def project__create(self) -> None:
        """Create a project"""
        try:
            project = self.client.create_project(
                account_id=self._resolve_parent_id(self.args.parent_id),
                billing_group_id=self.args.billing_group_id,
                cloud=self.args.cloud,
                copy_from_project=self.args.copy_from_project,
                project=self.args.project_name,
                tech_emails=self.args.tech_email,
                use_source_project_billing_group=self.args.use_source_project_billing_group,
            )
        except client.Error as ex:
            if not self.args.no_fail_if_exists or ex.response.status_code != HTTPStatus.CONFLICT:
                raise

            self.log.info("Project '%s' already exists", self.args.project_name)
            return

        self.config["default_project"] = self.args.project_name
        self.config.save()

        self._show_projects([dict(project)])
        self.log.info(
            "Project %r successfully created and set as default project",
            project["project_name"],
        )

    @arg.json
    @arg.project
    def project__details(self) -> None:
        """Show project details"""
        project_name = self.get_project()
        project = self.client.get_project(project=project_name)
        self._show_projects([dict(project)])

    @arg.json
    @arg.verbose
    def project__list(self) -> None:
        """List projects"""
        projects = self.client.get_projects()
        self._show_projects(projects, verbose=self.args.verbose)

    @arg.project
    @arg("--name", help="New project name")
    @arg.parent_id
    @arg.cloud
    @arg.tech_email
    def project__update(self) -> None:
        """Update a project"""
        project_name = self.get_project()
        try:
            project = self.client.update_project(
                new_project_name=self.args.name,
                account_id=self._resolve_parent_id(self.args.parent_id) if self.args.parent_id else None,
                cloud=self.args.cloud,
                project=project_name,
                tech_emails=self.args.tech_email,
            )
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' update failed".format(project_name))
        if self.args.name and self.config["default_project"] == project_name:
            self.config["default_project"] = project["project_name"]
            self.config.save()
        self._show_projects([dict(project)])
        self.log.info("Project %r successfully updated", project["project_name"])

    @arg.project
    @arg("--target-filepath", help="Project CA filepath", required=True)
    def project__ca_get(self) -> None:
        """Get project CA certificate"""
        project_name = self.get_project()
        try:
            result = self.client.get_project_ca(project=project_name)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' CA get failed".format(project_name))
        with open(self.args.target_filepath, "w", encoding="utf-8") as fp:
            fp.write(result["certificate"])

    @arg.project
    @arg.service_name
    @arg("--target-filepath", help="Filepath for storing CA certificate", required=True)
    @arg("ca")
    def service__ca__get(self) -> None:
        """Get service CA certificate"""
        project_name = self.get_project()
        result = self.client.get_service_ca(project=project_name, service=self.args.service_name, ca=self.args.ca)

        with open(self.args.target_filepath, "w", encoding="utf-8") as fp:
            fp.write(result["certificate"])

    @arg.project
    @arg.service_name
    @arg("--key-filepath", help="Filepath for storing private key", required=True)
    @arg("--cert-filepath", help="Filepath for storing certificate", required=True)
    @arg("keypair")
    def service__keypair__get(self) -> None:
        """Get service keypair"""
        project_name = self.get_project()
        result = self.client.get_service_keypair(
            project=project_name, service=self.args.service_name, keypair=self.args.keypair
        )

        with open(self.args.key_filepath, "w", encoding="utf-8") as fp:
            fp.write(result["key"])
        with open(self.args.cert_filepath, "w", encoding="utf-8") as fp:
            fp.write(result["certificate"])

    def _validate_service_cassandra_sstableloader(self) -> Mapping[str, Any]:
        """
        Raises an exception if the service type is not Cassandra, or if its user config doesn't have it set to sstableloader
        migration mode
        """
        service = self.client.get_service(project=self.get_project(), service=self.args.service_name)
        if service["service_type"] != "cassandra":
            raise argx.UserError("Service type is not 'cassandra' but {}".format(service["service_type"]))
        if not service["user_config"].get("migrate_sstableloader", False):
            raise argx.UserError("Service does not have migrate_sstableloader on")
        return service

    @arg.project
    @arg.service_name
    @arg(
        "-d",
        "--target-directory",
        help="Directory to write credentials to",
        required=False,
        default=os.getcwd(),
    )
    @arg("-p", "--password", help="Keystore and truststore password", default="changeit")
    @arg(
        "--preserve-pem",
        action="store_true",
        help=(
            "Keep PEM encoded unencrypted service CA and keypair files in addition to the Java keystore and truststore "
            "files created from them"
        ),
    )
    def service__sstableloader__get_credentials(self) -> None:
        """Download credentials and generate cassandra.yaml suitable for running Cassandra sstableloader"""
        self._validate_service_cassandra_sstableloader()

        project_name = self.get_project()
        client_keypair = self.client.get_service_keypair(
            project=project_name,
            service=self.args.service_name,
            keypair="cassandra_migrate_sstableloader_user",
        )
        internode_ca = self.client.get_service_ca(
            project=project_name,
            service=self.args.service_name,
            ca="cassandra_internode_service_nodes_ca",
        )
        project_ca = self.client.get_project_ca(project=project_name)

        if not os.path.exists(self.args.target_directory):
            os.makedirs(self.args.target_directory)

        client_key_path = os.path.join(self.args.target_directory, "sstableloader.key")
        client_cert_path = os.path.join(self.args.target_directory, "sstableloader.cert")
        internode_ca_path = os.path.join(self.args.target_directory, "internode-ca.cert")
        project_ca_path = os.path.join(self.args.target_directory, "project-ca.cert")

        try:
            with open(client_key_path, "w", encoding="utf-8") as fp:
                fp.write(client_keypair["key"])
            with open(client_cert_path, "w", encoding="utf-8") as fp:
                fp.write(client_keypair["certificate"])
            with open(internode_ca_path, "w", encoding="utf-8") as fp:
                fp.write(internode_ca["certificate"])
            with open(project_ca_path, "w", encoding="utf-8") as fp:
                fp.write(project_ca["certificate"])

            # Sstableloader accepts a regular cassandra.yaml and reads encryption settings for connecting to the native
            # transport port (client_encryption_options) and the SSL storage port (server_encryption_options).
            # Some options are boilerplate just used to avoid Cassandra/Java libraries to attempt to look up
            # keystore/truststore files from default locations, and failing when they do not exist, even if the actual
            # certificates/keys in them would not be used
            with open(os.path.join(self.args.target_directory, "cassandra.yaml"), "w", encoding="utf-8") as fp:
                fp.write(
                    """\
client_encryption_options:
    enabled: true
    optional: false
    keystore: sstableloader.keystore.p12
    keystore_password: {password}
    truststore: ./sstableloader.truststore.jks
    truststore_password: {password}
server_encryption_options:
    internode_encryption: all
    keystore: sstableloader.keystore.p12
    keystore_password: {password}
    truststore: ./sstableloader.truststore.jks
    truststore_password: {password}
""".format(
                        password=self.args.password
                    )
                )

            # The Project CA signs the certificate used by the Cassandra native transport, aka the regular client port
            # The internode CA signs the certificate used by SSL storage port, aka the internode port used to stream data
            for path, alias in [
                (project_ca_path, "Project"),
                (internode_ca_path, "Cassandra internode service nodes"),
            ]:
                subprocess.check_call(
                    [
                        "keytool",
                        "-importcert",
                        "-alias",
                        "{} CA".format(alias),
                        "-keystore",
                        os.path.join(self.args.target_directory, "sstableloader.truststore.jks"),
                        "-storepass",
                        self.args.password,
                        "-file",
                        path,
                        "-noprompt",
                    ]
                )
            # Connecting to the native transport port happens via username and password credentials, while connecting to
            # the SSL storage port requires this client certificate
            subprocess.check_call(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-out",
                    os.path.join(self.args.target_directory, "sstableloader.keystore.p12"),
                    "-inkey",
                    client_key_path,
                    "-in",
                    client_cert_path,
                    "-passout",
                    "pass:{}".format(self.args.password),
                ]
            )
        finally:
            # These are not used when connecting with the Java based sstableloader utility
            if not self.args.preserve_pem:
                for path in (
                    client_key_path,
                    client_cert_path,
                    internode_ca_path,
                    project_ca_path,
                ):
                    if os.path.isfile(path):
                        os.unlink(path)

    @arg.project
    @arg.service_name
    @arg(
        "--cassandra-yaml",
        default="cassandra.yaml",
        help="Path to cassandra.yaml configuration file",
    )
    def service__sstableloader__command(self) -> None:
        """Outputs a string that can be used to run the sstableloader utility to upload Cassandra data
        files directly to the internode port of a Cassandra cluster."""
        service = self._validate_service_cassandra_sstableloader()

        cassandra_component = None
        internode_component = None
        for component in service["components"]:
            if component["component"] == "cassandra" and component["route"] == "dynamic" and component["usage"] == "primary":
                cassandra_component = component
            elif (
                component["component"] == "cassandra_internode"
                and component["route"] == "dynamic"
                and component["usage"] == "primary"
            ):
                internode_component = component

        if cassandra_component is None or internode_component is None:
            raise ValueError("Cassandra service component information missing")

        print(
            "sstableloader -f {yaml} -d {hostname} -ssp {internode_port} -p {client_port} -u {user} -pw {password}".format(
                yaml=self.args.cassandra_yaml,
                hostname=cassandra_component["host"],
                internode_port=internode_component["port"],
                client_port=cassandra_component["port"],
                user=service["service_uri_params"]["user"],
                password=service["service_uri_params"]["password"],
            )
        )

    @arg.project
    @arg.email
    @arg(
        "--role",
        help="Project role for new invited user ('admin', 'operator', 'developer')",
    )
    def project__user_invite(self) -> None:
        """Invite a new user to the project"""
        project_name = self.get_project()
        try:
            self.client.invite_project_user(
                project=project_name,
                user_email=self.args.email,
                member_type=self.args.role,
            )
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' invite for {} failed".format(project_name, self.args.email))
        self.log.info("Invited %r into project %r", self.args.email, project_name)

    @arg.project
    @arg.email
    def project__user_remove(self) -> None:
        """Remove a user from the project"""
        project_name = self.get_project()
        try:
            self.client.remove_project_user(project=project_name, user_email=self.args.email)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' removal of user {} failed".format(project_name, self.args.email))
        self.log.info("Removed %r from project %r", self.args.email, project_name)

    @arg.json
    @arg.project
    def project__user_list(self) -> None:
        """Project user list"""
        project_name = self.get_project()
        try:
            user_list = self.client.list_project_users(project=project_name)
            layout = [["user_email", "member_type", "create_time"]]
            self.print_response(user_list, json=self.args.json, table_layout=layout)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project user listing for '{}' failed".format(project_name))

    @arg.json
    @arg.project
    def project__invite_list(self) -> None:
        """Project user list"""
        project_name = self.get_project()
        try:
            user_list = self.client.list_invited_project_users(project=project_name)
            layout = [["invited_user_email", "inviting_user_email", "member_type", "invite_time"]]
            self.print_response(user_list, json=self.args.json, table_layout=layout)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project user listing for '{}' failed".format(project_name))

    def _print_tags(self, tags: Mapping[str, Any]) -> None:
        layout = [["key", "value"]]
        self.print_response(
            [{"key": key, "value": value} for key, value in tags["tags"].items()],
            json=self.args.json,
            table_layout=layout,
        )

    @staticmethod
    def _parse_tag_arg(tag: str) -> tuple[str, str]:
        if "=" not in tag:
            raise argx.UserError(f"Invalid tag key-value pair '{tag}', expected '<KEY>=<VALUE>'")
        key, value = tag.split("=", maxsplit=1)
        return key, value

    def _tag_update_body_from_args(self) -> Mapping[str, str | None]:
        tag_updates: dict[str, str | None] = {key: None for key in self.args.remove_tag}
        tag_updates.update(dict(self._parse_tag_arg(tag) for tag in self.args.add_tag))
        return tag_updates

    def _tag_replace_body_from_args(self) -> Mapping[str, str]:
        return dict(self._parse_tag_arg(tag) for tag in self.args.tag)

    @arg.json
    @arg.project
    def project__tags__list(self) -> None:
        """List project tags"""
        project_name = self.get_project()
        tags = self.client.list_project_tags(project=project_name)
        self._print_tags(tags)

    @arg.json
    @arg.project
    @arg("--add-tag", help="Add a new tag (key=value)", action="append", default=[])
    @arg("--remove-tag", help="Remove the named tag", action="append", default=[])
    def project__tags__update(self) -> None:
        """Add or remove project tags"""
        project_name = self.get_project()
        response = self.client.update_project_tags(project=project_name, tag_updates=self._tag_update_body_from_args())
        print(response["message"])

    @arg.json
    @arg.project
    @arg("--tag", help="Tag for project (key=value)", action="append", default=[])
    def project__tags__replace(self) -> None:
        """Replace project tags, deleting any old ones first"""
        project_name = self.get_project()
        response = self.client.replace_project_tags(project=project_name, tags=self._tag_replace_body_from_args())
        print(response["message"])

    @arg.project
    @arg(
        "--output",
        help="Output extension(CSV or SPDX), for the SBOM report.",
        required=True,
    )
    def project__generate_sbom(self) -> None:
        """Generate SBOM report from a given project"""
        allowed_extensions = ["csv", "spdx"]
        if self.args.output not in allowed_extensions:
            raise argx.UserError(f"Unsupported output extension. Please, use one from this list: {allowed_extensions}")

        response = self.client.get_project_sbom_download_url(project=self.get_project(), output_format=self.args.output)

        download_url = response.get("download_url")
        if not download_url:
            raise argx.UserError("Cannot retrieve a SBOM download url from server.")

        sbom_url = {"sbom_report_url": f"{self.client.base_url}{self.client.api_prefix}{download_url}"}
        self.print_response(sbom_url)

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

    def pre_run(self, func: Callable[[], int | None]) -> None:
        self.client = self.client_factory(
            base_url=self.args.url,
            show_http=self.args.show_http,
            request_timeout=self.args.request_timeout,
        )
        # Always set CA if we have anything set at the command line or in the env
        if self.args.auth_ca is not None:
            self.client.set_ca(self.args.auth_ca)
        if func == self.user__create:
            # "user create" doesn't use authentication (yet)
            return

        if not getattr(func, "no_auth", False):
            auth_token = self._get_auth_token()
            if auth_token:
                self.client.set_auth_token(auth_token)
            elif not getattr(func, "optional_auth", False):
                raise argx.UserError("not authenticated: please login first with 'avn user login'")

    @arg.json
    @arg.organization_id
    @arg("--name", help="Application User name", required=True)
    def application_user__create(self) -> None:
        """Create an application user"""
        app_user = self.client.create_application_user(
            organization_id=self.args.organization_id,
            name=self.args.name,
        )
        layout = [["name", "user_email", "user_id", "is_super_admin"]]
        self.print_response(app_user, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    def application_user__info(self) -> None:
        """Get profile information for an application user"""
        app_user = self.client.get_application_user(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
        )
        layout = [["name", "user_email", "user_id", "is_super_admin"]]
        self.print_response(app_user, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.organization_id
    def application_user__list(self) -> None:
        """List application users for an organization"""
        app_users = self.client.list_application_users(organization_id=self.args.organization_id)
        layout = [["name", "user_email", "user_id", "is_super_admin"]]
        self.print_response(app_users, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    @arg("--name", help="Application User name", required=True)
    def application_user__update(self) -> None:
        """Update the profile information for an application user"""
        app_user = self.client.update_application_user(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
            name=self.args.name,
        )
        layout = [["name", "user_email", "user_id", "is_super_admin"]]
        self.print_response(app_user, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.force
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    def application_user__delete(self) -> None:
        """Permanently delete an application user"""
        if not self.args.force:
            self.print_boxed(
                [
                    "Deleting an application user cannot be undone and all associated tokens will be invalidated!",
                ]
            )

        if not self.confirm("Confirm delete (y/N)?"):
            raise argx.UserError("Aborted")

        self.client.delete_application_user(organization_id=self.args.organization_id, user_id=self.args.user_id)
        print(f"Application user {self.args.user_id} deleted successfully.")

    @arg.json
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    @arg("--description", help="Token description", required=True)
    @arg(
        "--max-age-seconds",
        type=int,
        help="Time the token remains valid since creation (or since last use if extend_when_used is true) "
        "expressed in seconds. The token will never expire if not specified",
    )
    @arg(
        "--extend-when-used",
        action="store_true",
        default=False,
        help="Extend token expiration time when token is used. Only applicable if max_age_seconds is specified",
    )
    @arg(
        "--ip-allowlist",
        action="append",
        default=[],
        help="IP allowlist for the token. Can be specified multiple times to add multiple IPs or CIDRs",
    )
    @arg(
        "--scopes",
        action="append",
        default=[],
        help="Scopes for the token. Can be specified multiple times to add multiple scopes",
    )
    def application_user__token__create(self) -> None:
        """Creates a token for an application user."""
        if self.args.extend_when_used and not self.args.max_age_seconds:
            raise argx.UserError("extend_when_used can only be used if max_age_seconds is specified")
        token_info = self.client.create_application_user_token(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
            description=self.args.description,
            max_age_seconds=self.args.max_age_seconds,
            extend_when_used=self.args.extend_when_used,
            ip_allowlist=self.args.ip_allowlist,
            scopes=self.args.scopes,
        )
        layout = [["full_token", "token_prefix"]]
        self.print_boxed(
            [
                "Copy and safely store the full token value. You cannot get the token later.",
            ]
        )
        self.print_response(token_info, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    @arg("--verbose", action="store_true", default=False, help="Show more details")
    def application_user__token__list(self) -> None:
        """List all tokens for an application user."""
        tokens = self.client.list_application_user_tokens(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
        )
        layout = [
            "token_prefix",
            "description",
            "last_used_time",
            "expiry_time",
            "currently_active",
        ]
        if self.args.verbose:
            layout.extend(
                [
                    "create_time",
                    "created_manually",
                    "extend_when_used",
                    "ip_allowlist",
                    "last_ip",
                    "last_user_agent_human_readable",
                    "max_age_seconds",
                    "scopes",
                ]
            )
        self.print_response(tokens, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg("--verbose", action="store_true", default=False, help="Show more details")
    @arg("user_id", help="Application User ID")
    @arg("token_prefix", help="Token prefix to get info for")
    def application_user__token__info(self) -> None:
        """Show info on the specified token for an application user."""
        tokens = self.client.list_application_user_tokens(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
        )
        token = next((token for token in tokens if token["token_prefix"] == self.args.token_prefix), None)
        if not token:
            raise argx.UserError(f"Token with prefix '{self.args.token_prefix}' not found for user {self.args.user_id}")

        layout = [
            "token_prefix",
            "description",
            "last_used_time",
            "expiry_time",
            "currently_active",
        ]
        if self.args.verbose:
            layout.extend(
                [
                    "create_time",
                    "created_manually",
                    "extend_when_used",
                    "ip_allowlist",
                    "last_ip",
                    "last_user_agent_human_readable",
                    "max_age_seconds",
                    "scopes",
                ]
            )
        self.print_response(token, json=self.args.json, table_layout=layout, single_item=True)

    @arg.json
    @arg.force
    @arg.organization_id
    @arg("user_id", help="Application User ID")
    @arg("token_prefix", help="Token prefix to delete")
    def application_user__token__revoke(self) -> None:
        """Permanently revoke the specified token for the application user."""
        if not self.args.force:
            self.print_boxed(
                [
                    "Revoking an application user's access token cannot be undone!",
                ]
            )

        if not self.confirm("Confirm revoke (y/N)?"):
            raise argx.UserError("Aborted")
        self.client.delete_application_user_token(
            organization_id=self.args.organization_id,
            user_id=self.args.user_id,
            token_prefix=self.args.token_prefix,
        )
        print(f"Token {self.args.token_prefix} (application user id: {self.args.user_id}) revoked successfully.")

    @arg.json
    @arg.force
    @arg.organization_id
    @arg("--resource-type", choices=["organization", "organization_unit", "project"], help="Resource type", required=True)
    @arg("--resource-id", help="Resource ID, required if resource_type is not 'organization'")
    @arg("--principal-id", help="Principal ID to which permissions are assigned")
    @arg("--principal-type", choices=["user", "user_group"], help="Principal type to which permissions are assigned")
    @arg(
        "--permission",
        action="append",
        dest="permissions",
        default=[],
        metavar="PERMISSION",
        help="Permissions to assign. Can be specified multiple times to add multiple permissions",
    )
    def permissions__set(self) -> None:
        """Set (replacing the previous assignment for the target principal) permissions
        for the given principal (in the context of the given resource)"""
        if self.args.resource_type != "organization" and not self.args.resource_id:
            raise argx.UserError(f"resource_id is required when resource_type is '{self.args.resource_type}'")

        if not self.args.permissions and not self.args.force:
            self.print_boxed(
                [
                    f"You are going to remove all permissions for principal "
                    f"{self.args.principal_id} (principal_type={self.args.principal_type}).",
                ]
            )
            if not self.confirm("Do you want to proceed (y/N)?"):
                raise argx.UserError("Aborted")

        resource_id = self.args.organization_id if self.args.resource_type == "organization" else self.args.resource_id
        if not self.args.force:
            _current_permissions = self.client.list_permissions(
                organization_id=self.args.organization_id,
                resource_type=self.args.resource_type,
                resource_id=resource_id,
            )
            current_permissions = set()
            for perm in self._filter_permissions_by_principal(_current_permissions):
                current_permissions.update(perm["permissions"])
            new_permissions = set(self.args.permissions)
            removed = current_permissions - new_permissions
            added = new_permissions - current_permissions
            if removed:
                print("The following permissions are going to be removed:")
                for rem_perm in removed:
                    print(f"- {rem_perm}")
            if added:
                print("The following permissions are going to be added:")
                for add_perm in added:
                    print(f"+ {add_perm}")

            if added or removed:
                if not self.confirm("Do you want to proceed (y/N)?"):
                    raise argx.UserError("Aborted")

        self.client.update_permissions(
            organization_id=self.args.organization_id,
            resource_type=self.args.resource_type,
            resource_id=resource_id,
            principal_id=self.args.principal_id,
            principal_type=self.args.principal_type,
            permissions=self.args.permissions,
        )
        print("Done")

    def _filter_permissions_by_principal(self, permissions: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        return [
            permission
            for permission in permissions
            if (
                (self.args.principal_id is None or permission["principal_id"] == self.args.principal_id)
                and (self.args.principal_type is None or permission["principal_type"] == self.args.principal_type)
            )
        ]

    @arg.json
    @arg.organization_id
    @arg("--resource-type", choices=["organization", "organization_unit", "project"], help="Resource type", required=True)
    @arg("--resource-id", help="Resource ID, required if resource_type is not 'organization'")
    @arg("--principal-id", help="Filter results to only list permissions for the given principal ID")
    @arg(
        "--principal-type",
        choices=["user", "user_group"],
        help="Filter results to only list permissions for the given principal type",
    )
    def permissions__list(self) -> None:
        """List permissions"""
        if self.args.resource_type != "organization" and not self.args.resource_id:
            raise argx.UserError(f"resource_id is required when resource_type is '{self.args.resource_type}'")
        resource_id = self.args.organization_id if self.args.resource_type == "organization" else self.args.resource_id
        permissions = self.client.list_permissions(
            organization_id=self.args.organization_id,
            resource_type=self.args.resource_type,
            resource_id=resource_id,
        )
        if self.args.principal_id or self.args.principal_type:
            permissions = self._filter_permissions_by_principal(permissions)

        if not permissions:
            print("No permissions found")
            return
        layout = [["principal_id", "principal_type", "permissions"]]
        self.print_response(permissions, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    def credits__list(self) -> None:
        """List claimed credits"""
        project_name = self.get_project()
        project_credits = self.client.list_project_credits(project=project_name)
        layout = [["code", "remaining_value"]]
        self.print_response(project_credits, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    @arg("code", help="Credit code")
    def credits__claim(self) -> None:
        """Claim a credit code"""
        project_name = self.get_project()
        result = self.client.claim_project_credit(project=project_name, credit_code=self.args.code)
        if self.args.json:
            self.print_response(result, json=True)

    def _print_billing_groups(self, billing_groups: Sequence[dict[str, Any]]) -> None:
        for billing_group in billing_groups:
            billing_group["credit_card"] = self._format_card_info(billing_group)
            billing_group["billing_emails"] = [item["email"] for item in billing_group["billing_emails"]]
        layout: list = [
            [
                "billing_group_id",
                "billing_group_name",
                "account_name",
            ]
        ]
        if self.args.verbose:
            layout.extend(
                [
                    "payment_method",
                    "credit_card",
                    "vat_id",
                    "billing_currency",
                    "estimated_balance_usd",
                    "estimated_balance_local",
                    "billing_extra_text",
                    "billing_emails",
                    "company",
                    "address_lines",
                    "country_code",
                    "city",
                    "state",
                    "zip_code",
                    "billing_address",
                ]
            )
        self.print_response(billing_groups, json=self.args.json, table_layout=layout)

    @arg("name", help="Billing group name")
    @arg("--account-id", required=True, help="Account ID of the project")
    @arg.card_id
    @arg.vat_id
    @arg.billing_currency
    @arg.billing_extra_text
    @arg.billing_email
    @arg("--company", help="Company name")
    @arg("--address-line", action="append", help="Address line")
    @arg.country_code
    @arg("--city", help="City")
    @arg("--state", help="State / Province")
    @arg("--zip-code", help="ZIP / Postal code")
    @arg(
        "--no-fail-if-exists",
        action="store_true",
        default=False,
        help="Do not fail if billing group already exists",
    )
    @arg.json
    @arg.verbose
    def billing_group__create(self) -> None:
        """Create a billing group"""
        billing_group = self.client.create_billing_group(
            billing_group_name=self.args.name,
            account_id=self.args.account_id,
            card_id=self.args.card_id,
            vat_id=self.args.vat_id,
            billing_currency=self.args.billing_currency,
            billing_extra_text=self.args.billing_extra_text,
            billing_emails=self.args.billing_email,
            company=self.args.company,
            address_lines=self.args.address_line,
            country_code=self.args.country_code,
            city=self.args.city,
            state=self.args.state,
            zip_code=self.args.zip_code,
        )
        self._print_billing_groups([dict(billing_group)])

    @arg.billing_group
    @arg("--name", help="Billing group name")
    @arg("--account-id", help="Account ID of the project")
    @arg.card_id
    @arg.vat_id
    @arg.billing_currency
    @arg.billing_extra_text
    @arg.billing_email
    @arg("--company", help="Company name")
    @arg("--address-line", action="append", help="Address line")
    @arg.country_code
    @arg("--city", help="City")
    @arg("--state", help="State / Province")
    @arg("--zip-code", help="ZIP / Postal code")
    def billing_group__update(self) -> None:
        """Update a billing group"""
        self.client.update_billing_group(
            billing_group=self.args.id,
            billing_group_name=self.args.name,
            account_id=self.args.account_id,
            card_id=self.args.card_id,
            vat_id=self.args.vat_id,
            billing_currency=self.args.billing_currency,
            billing_extra_text=self.args.billing_extra_text,
            billing_emails=self.args.billing_email,
            company=self.args.company,
            address_lines=self.args.address_line,
            country_code=self.args.country_code,
            city=self.args.city,
            state=self.args.state,
            zip_code=self.args.zip_code,
        )

    @arg.json
    @arg.verbose
    def billing_group__list(self) -> None:
        """Lists billing groups"""
        billing_groups = self.client.get_billing_groups()
        self._print_billing_groups(billing_groups)

    @arg.billing_group
    @arg.json
    @arg.verbose
    def billing_group__get(self) -> None:
        """Get a project"""
        billing_group = self.client.get_billing_group(billing_group=self.args.id)
        self._print_billing_groups([dict(billing_group)])
        if self.args.verbose and not self.args.json:
            print("Billing group projects")
            projects = self.client.get_billing_group_projects(billing_group=self.args.id)
            if not projects:
                print("None")
                return
            layout = [
                [
                    "project_name",
                    "estimated_balance",
                    "available_credits",
                ]
            ]
            self.print_response(projects, json=False, table_layout=layout)

    @arg.billing_group
    def billing_group__delete(self) -> None:
        """Delete a project"""
        self.client.delete_billing_group(billing_group=self.args.id)

    @arg.billing_group
    @arg("projects", nargs="+", help="Project names")
    def billing_group__assign_projects(self) -> None:
        """Assign projects to billing group"""
        self.client.assign_projects_to_billing_group(
            billing_group=self.args.id,
            project_names=self.args.projects,
        )

    @arg.billing_group
    @arg.json
    @arg("-n", "--limit", type=int, default=100, help="Get up to N rows of logs")
    def billing_group__events(self) -> None:
        """View project event logs"""
        events = self.client.get_billing_group_events(billing_group=self.args.id, limit=self.args.limit)
        layout = ["create_time", "actor", "event_desc"]
        self.print_response(events, json=self.args.json, table_layout=layout)

    @arg.billing_group
    @arg.json
    def billing_group__credits_list(self) -> None:
        """List claimed credits"""
        result = self.client.list_billing_group_credits(billing_group=self.args.id)
        layout = [["code", "remaining_value"]]
        self.print_response(result, json=self.args.json, table_layout=layout)

    @arg.billing_group
    @arg.json
    @arg("code", help="Credit code")
    def billing_group__credits_claim(self) -> None:
        """Claim a credit code"""
        result = self.client.claim_billing_group_credit(billing_group=self.args.id, credit_code=self.args.code)
        if self.args.json:
            self.print_response(result, json=True)

    @arg.billing_group
    @arg(
        "--sort",
        choices=["invoice_number", "period_begin", "period_end", "state", "currency", "total_inc_vat", "total_vat_zero"],
    )
    @arg.json
    @arg.verbose
    def billing_group__invoice_list(self) -> None:
        """List billing group invoices"""
        result = self.client.list_billing_group_invoices(billing_group=self.args.id, sort=self.args.sort)
        layout: list = [
            [
                "invoice_number",
                "period_begin",
                "period_end",
                "state",
                "total_inc_vat",
                "total_vat_zero",
            ]
        ]
        if self.args.verbose:
            layout.extend(["currency", "download"])
        self.print_response(result, json=self.args.json, table_layout=layout)

    @arg.billing_group
    @arg("invoice", help="Invoice number")
    @arg.json
    def billing_group__invoice_lines(self) -> None:
        """Get billing group invoice lines"""
        result = self.client.get_billing_group_invoice_lines(billing_group=self.args.id, invoice_number=self.args.invoice)
        layout = [
            [
                "timestamp_begin",
                "timestamp_end",
                "line_type",
                "description",
                "line_total_local",
                "local_currency",
                "line_total_usd",
            ]
        ]
        self.print_response(result, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    @arg("--service", help="Related service name")
    @arg(
        "--severity",
        required=True,
        choices=["low", "high", "critical"],
        help="Ticket severity",
    )
    @arg("--title", required=True, help="Short description")
    @arg("--description", required=True, help="Longer description")
    def ticket__create(self) -> None:
        """Create a support ticket"""
        project_name = self.get_project()
        ticket = self.client.create_ticket(
            description=self.args.description,
            project=project_name,
            service=self.args.service,
            severity=self.args.severity,
            title=self.args.title,
        )
        self.print_response(result=ticket, json=self.args.json)

    @arg.json
    @arg.project
    @arg("--state", required=False, help="Ticket state", choices=["closed", "open"])
    def ticket__list(self) -> None:
        """List support tickets for a project"""
        project_name = self.get_project()
        result = self.client.list_tickets(project=project_name)

        tickets = result["tickets"]
        if self.args.state:
            tickets = [ticket for ticket in tickets if ticket["state"] == self.args.state]

        layout = [
            "ticket_id",
            "severity",
            "state",
            "title",
            "project_name",
            "service_name",
            "create_time",
            "description",
            "update_time",
            "user_email",
            "user_real_name",
        ]
        self.print_response(result=tickets, table_layout=layout, json=self.args.json)

    @arg.json
    @arg.project
    def service__versions(self) -> None:
        """List service versions"""
        project = self.get_project(raise_if_none=False, fallback_to_default_project=False)
        service_versions = self._get_service_versions(project=project)
        layout = [
            "service_type",
            "major_version",
            "state",
            "availability_start_time",
            "availability_end_time",
            "aiven_end_of_life_time",
            "upstream_end_of_life_time",
            "termination_time",
            "end_of_life_help_article_url",
        ]
        self.print_response(service_versions, table_layout=layout, json=self.args.json)

    @arg.json
    @arg.project
    @arg.service_name
    def service__tags__list(self) -> None:
        """List service tags"""
        tags = self.client.list_service_tags(project=self.get_project(), service=self.args.service_name)
        self._print_tags(tags)

    @arg.json
    @arg.project
    @arg.service_name
    @arg("--add-tag", help="Add a new tag (key=value)", action="append", default=[])
    @arg("--remove-tag", help="Remove the named tag", action="append", default=[])
    def service__tags__update(self) -> None:
        """Add or remove service tags"""
        response = self.client.update_service_tags(
            project=self.get_project(),
            service=self.args.service_name,
            tag_updates=self._tag_update_body_from_args(),
        )
        print(response["message"])

    @arg.json
    @arg.project
    @arg.service_name
    @arg("--tag", help="Tag for service (key=value)", action="append", default=[])
    def service__tags__replace(self) -> None:
        """Replace service tags, deleting any old ones first"""
        response = self.client.replace_service_tags(
            project=self.get_project(),
            service=self.args.service_name,
            tags=self._tag_replace_body_from_args(),
        )
        print(response["message"])

    @arg.json
    @arg.account_id
    @arg("-n", "--name", required=True, help="OAuth2 application name")
    @arg(
        "--redirect-uri",
        required=True,
        help="Redirect URI",
    )
    @arg(
        "-d",
        "--description",
        required=False,
        help="App description",
    )
    def account__oauth2_client__create(self) -> None:
        """Create new OAuth2 client."""
        oauth2_client = self.client.create_oauth2_client(
            self.args.account_id,
            name=self.args.name,
            description=self.args.description,
        )

        client_id = oauth2_client["client_id"]

        try:
            redirect = self.client.create_oauth2_client_redirect(self.args.account_id, client_id, self.args.redirect_uri)
            secret = self.client.create_oauth2_client_secret(self.args.account_id, client_id)

            oauth2_client["redirect_uri"] = redirect["redirect_uri"]
            oauth2_client["secret"] = secret["secret"]
        except Exception:
            self.client.delete_oauth2_client(self.args.account_id, client_id)
            raise

        table_layout = ["client_id", "name", "redirect_uri", "secret"]
        self.print_response(oauth2_client, json=self.args.json, single_item=True, table_layout=table_layout)

    @arg.json
    @arg.account_id
    def account__oauth2_client__list(self) -> None:
        """List OAuth2 client configuration."""

        oauth2_clients = self.client.list_oauth2_clients(self.args.account_id)
        table_layout = ["client_id", "name", "description"]
        self.print_response(oauth2_clients, json=self.args.json, table_layout=table_layout)

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

    @arg.project
    @arg.service_name
    def service__flink__list_applications(self) -> None:
        """List Flink applications"""
        self.print_response(
            self.client.flink_list_applications(
                project=self.get_project(),
                service=self.args.service_name,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.json_path_or_string("application_properties")
    def service__flink__create_application(self) -> None:
        """Create Flink application"""
        self.print_response(
            self.client.flink_create_application(
                project=self.get_project(),
                service=self.args.service_name,
                application_properties=self.args.application_properties,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    def service__flink__get_application(self) -> None:
        """Get Flink application"""
        self.print_response(
            self.client.flink_get_application(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.json_path_or_string("application_properties")
    def service__flink__update_application(self) -> None:
        """Update Flink application"""
        self.print_response(
            self.client.flink_update_application(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                application_properties=self.args.application_properties,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    def service__flink__delete_application(self) -> None:
        """Delete Flink application"""
        self.print_response(
            self.client.flink_delete_application(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.json_path_or_string("application_version_properties")
    def service__flink__create_application_version(self) -> None:
        """Create Flink application version"""
        self.print_response(
            self.client.flink_create_application_version(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                application_version_properties=self.args.application_version_properties,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.json_path_or_string("application_version_properties")
    def service__flink__validate_application_version(self) -> None:
        """Validate Flink application version"""
        self.print_response(
            self.client.flink_validate_application_version(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                application_version_properties=self.args.application_version_properties,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_application_version_id
    def service__flink__get_application_version(self) -> None:
        """Get Flink application version"""
        self.print_response(
            self.client.flink_get_application_version(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                application_version_id=self.args.application_version_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_application_version_id
    def service__flink__delete_application_version(self) -> None:
        """Delete Flink application version"""
        self.print_response(
            self.client.flink_delete_application_version(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                application_version_id=self.args.application_version_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    def service__flink__list_application_deployments(self) -> None:
        """List Flink application deployments"""
        self.print_response(
            self.client.flink_list_application_deployments(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_deployment_id
    def service__flink__get_application_deployment(self) -> None:
        """Get Flink application deployment"""
        self.print_response(
            self.client.flink_get_application_deployment(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                deployment_id=self.args.deployment_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.json_path_or_string("deployment_properties")
    def service__flink__create_application_deployment(self) -> None:
        """Create Flink application deployment"""
        self.print_response(
            self.client.flink_create_application_deployment(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                deployment_properties=self.args.deployment_properties,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_deployment_id
    def service__flink__delete_application_deployment(self) -> None:
        """Delete Flink application deployment"""
        self.print_response(
            self.client.flink_delete_application_deployment(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                deployment_id=self.args.deployment_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_deployment_id
    def service__flink__stop_application_deployment(self) -> None:
        """Stop Flink application deployment"""
        self.print_response(
            self.client.flink_stop_application_deployment(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                deployment_id=self.args.deployment_id,
            ),
        )

    @arg.project
    @arg.service_name
    @arg.flink_application_id
    @arg.flink_deployment_id
    def service__flink__cancel_application_deployments(self) -> None:
        """Cancel Flink application deployment"""
        self.print_response(
            self.client.flink_cancel_application_deployment(
                project=self.get_project(),
                service=self.args.service_name,
                application_id=self.args.application_id,
                deployment_id=self.args.deployment_id,
            ),
        )

    @arg.project
    @arg.service_name
    def service__custom_file__list(self) -> None:
        """List all the custom files for the specified service"""
        self.print_response(
            self.client.custom_file_list(
                project=self.get_project(),
                service=self.args.service_name,
            ),
        )

    @arg.project
    @arg.service_name
    @arg("--file_id", help="A file ID, usually an uuid4 string", required=True)
    @arg("--target_filepath", help="Where to save the file downloaded")
    @arg("--stdout_write", help="Write to the stdout instead of file", action="store_true")
    def service__custom_file__get(self) -> None:
        """
        Download the custom file for the specified service and ID
        Requires at least `--target_filepath` or `--stdout_write`, but able to handle both
        """
        if not (self.args.target_filepath or self.args.stdout_write):
            raise argx.UserError("You need to specify `--target_filepath` or `--stdout_write` or both")

        result = self.client.custom_file_get(
            project=self.get_project(),
            service=self.args.service_name,
            file_id=self.args.file_id,
        )

        if self.args.target_filepath:
            with open(self.args.target_filepath, "wb") as f:
                f.write(result)

        if self.args.stdout_write:
            print(result.decode("utf-8"))

    @arg.project
    @arg.service_name
    @arg("--file_path", help="A path to the file", required=True)
    @arg("--file_type", choices=["synonyms", "stopwords", "wordnet"], required=True)
    @arg("--file_name", help="A name for the file", required=True)
    def service__custom_file__upload(self) -> None:
        """Upload custom file for the specified service"""
        with open(self.args.file_path, "rb") as f:
            self.print_response(
                self.client.custom_file_upload(
                    project=self.get_project(),
                    service=self.args.service_name,
                    file_type=self.args.file_type,
                    file_name=self.args.file_name,
                    file_object=f,
                ),
            )

    @arg.project
    @arg.service_name
    @arg("--file_path", help="A path to the file", required=True)
    @arg("--file_id", help="A file ID, usually an uuid4 string", required=True)
    def service__custom_file__update(self) -> None:
        """Update custom file for the specified service and ID"""
        with open(self.args.file_path, "rb") as f:
            self.print_response(
                self.client.custom_file_update(
                    project=self.get_project(),
                    service=self.args.service_name,
                    file_id=self.args.file_id,
                    file_object=f,
                ),
            )

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

    @arg.json
    @arg.organization_id
    @arg.verbose
    def organization__vpc__list(self) -> None:
        """List VPCs in an organization"""
        vpcs = self.client.list_organization_vpcs(organization_id=self.args.organization_id).get("vpcs", [])
        output = [
            {
                **vpc,
                "cloud_name": ",".join([cloud["cloud_name"] for cloud in vpc["clouds"]]),
                "network_cidr": ",".join([cloud["network_cidr"] for cloud in vpc["clouds"]]),
            }
            for vpc in vpcs
        ]

        layout = ["organization_vpc_id", "cloud_name", "network_cidr", "state"]
        if self.args.verbose:
            layout += ["create_time", "update_time"]

        self.print_response(output, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg("--organization-vpc-id", required=True)
    @arg.verbose
    def organization__vpc__get(self) -> None:
        """Show a single VPCs in an organization"""
        vpc = self.client.get_organization_vpc(
            organization_id=self.args.organization_id,
            organization_vpc_id=self.args.organization_vpc_id,
        )
        layout = ["organization_vpc_id", "clouds", "state"]
        if self.args.verbose:
            layout += ["create_time", "update_time"]
        self.print_response([vpc], json=self.args.json, table_layout=layout)

    @arg.json
    @arg.organization_id
    @arg.cloud
    @arg(
        "--network-cidr",
        help="The network range for the project VPC in CIDR format (a.b.c.d/e)",
        required=True,
    )
    def organization__vpc__create(self) -> None:
        """Create a new VPC in an organization"""
        vpc = self.client.create_organization_vpc(
            organization_id=self.args.organization_id,
            cloud=self.args.cloud,
            network_cidr=self.args.network_cidr,
            peering_connections=[],
        )
        self.print_response([vpc], json=self.args.json)

    @arg.json
    @arg.organization_id
    @arg("--organization-vpc-id", required=True)
    def organization__vpc__delete(self) -> None:
        """Delete a VPC in an organization"""
        vpc = self.client.delete_organization_vpc(
            organization_id=self.args.organization_id,
            organization_vpc_id=self.args.organization_vpc_id,
        )
        self.print_response([vpc], json=self.args.json)

    @arg.json
    @arg.organization_id
    @arg("--organization-vpc-id", required=True)
    @arg("--peer-cloud-account", required=True, help=_peer_cloud_account_help)
    @arg("--peer-vpc", required=True, help=_peer_vpc_help)
    @arg("--peer-region", help=_peer_region_help)
    @arg("--peer-resource-group", help=_peer_resource_group_help)
    @arg("--peer-azure-app-id", help="Azure app object ID")
    @arg("--peer-azure-tenant-id", help="Azure AD tenant ID")
    @arg(
        "--user-peer-network-cidr",
        help="User-defined peer network IP range for routing/firewall",
        action="append",
        dest="user_peer_network_cidrs",
    )
    def organization__vpc__peering_connection__create(self) -> None:
        """Create a VPC peering connection for an organization VPC"""
        peering_connection = self.client.organization_vpc_peering_connection_create(
            organization_id=self.args.organization_id,
            vpc_id=self.args.organization_vpc_id,
            peer_cloud_account=self.args.peer_cloud_account,
            peer_vpc=self.args.peer_vpc,
            peer_region=self.args.peer_region,
            peer_resource_group=self.args.peer_resource_group,
            peer_azure_app_id=self.args.peer_azure_app_id,
            peer_azure_tenant_id=self.args.peer_azure_tenant_id,
        )
        layout = [
            "peer_cloud_account",
            "peer_resource_group",
            "peer_vpc",
            "peer_region",
            "state",
        ]
        self.print_response(
            [dict(peering_connection, peer_resource_group=peering_connection.get("peer_resource_group"))],
            json=self.args.json,
            table_layout=layout,
        )

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--organization-vpc-id", required=True)
    @arg("--peering-connection-id", required=True)
    @arg.json
    def organization__vpc__peering_connection__delete(self) -> None:
        """Delete a VPC peering connection of an organization VPC"""
        peering_connection = self.client.organization_vpc_peering_connection_delete(
            organization_id=self.args.organization_id,
            vpc_id=self.args.organization_vpc_id,
            peering_connection_id=self.args.peering_connection_id,
        )
        layout = [
            "peer_cloud_account",
            "peer_resource_group",
            "peer_vpc",
            "peer_region",
            "state",
        ]
        self.print_response(
            [dict(peering_connection, peer_resource_group=peering_connection.get("peer_resource_group"))],
            json=self.args.json,
            table_layout=layout,
        )

    @arg.json
    @arg.organization_id
    @arg("--organization-vpc-id", required=True)
    @arg.verbose
    def organization__vpc__peering_connection__list(self) -> None:
        """Show a single VPCs in an organization"""
        peering_connections = self.client.get_organization_vpc(
            organization_id=self.args.organization_id,
            organization_vpc_id=self.args.organization_vpc_id,
        )["peering_connections"]
        layout = [
            "peering_connection_id",
            "peer_cloud_account",
            "peer_resource_group",
            "peer_vpc",
            "peer_region",
            "state",
        ]
        if self.args.verbose:
            layout += ["create_time", "update_time"]
        self.print_response(peering_connections, json=self.args.json, table_layout=layout)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg.json
    def organization__vpc__clouds__list(self) -> None:
        """List clouds available for creating organization VPCs."""
        clouds = self.client.organization_vpc_clouds_list(organization_id=self.args.organization_id)
        self.print_response(clouds, json=self.args.json)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--organization-vpc-id", required=True)
    @arg("--peering-connection-id", required=True)
    @arg("cidrs", nargs="+", metavar="CIDR")
    @arg.json
    def organization__vpc__peering_connection__user_peer_network_cidrs__add(self) -> None:
        """Add user peer network CIDRs for an organization VPC peering connection."""
        self.client.organization_vpc_user_peer_network_cidrs_update(
            organization_id=self.args.organization_id,
            organization_vpc_id=self.args.organization_vpc_id,
            peering_connection_id=self.args.peering_connection_id,
            add=[{"cidr": cidr} for cidr in self.args.cidrs],
        )

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--organization-vpc-id", required=True)
    @arg("--peering-connection-id", required=True)
    @arg("cidrs", nargs="+", metavar="CIDR")
    @arg.json
    def organization__vpc__peering_connection__user_peer_network_cidrs__delete(self) -> None:
        """Delete user peer network CIDRs from an organization VPC peering connection."""
        self.client.organization_vpc_user_peer_network_cidrs_update(
            organization_id=self.args.organization_id,
            organization_vpc_id=self.args.organization_vpc_id,
            peering_connection_id=self.args.peering_connection_id,
            delete=self.args.cidrs,
        )

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

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--deployment-model", required=True, help="Deployment model for the BYOC cloud")
    @arg("--cloud-provider", required=True, help="Cloud provider to create the BYOC cloud in")
    @arg("--cloud-region", required=True, help="Region for the BYOC cloud")
    @arg("--reserved-cidr", required=True, help="The CIDR for the VPC to create for the custom cloud environment")
    @arg("--display-name", required=True, help="User set display name for the custom cloud environment")
    def byoc__create(self) -> None:
        """Create a new Bring Your Own Cloud configuration."""
        output = self.client.byoc_create(
            organization_id=self.args.organization_id,
            deployment_model=self.args.deployment_model,
            cloud_provider=self.args.cloud_provider,
            cloud_region=self.args.cloud_region,
            reserved_cidr=self.args.reserved_cidr,
            display_name=self.args.display_name,
        )
        self.print_response(output)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--deployment-model", help="Deployment model for the BYOC cloud")
    @arg("--cloud-provider", help="Cloud provider to create the BYOC cloud in")
    @arg("--cloud-region", help="Region for the BYOC cloud")
    @arg("--reserved-cidr", help="The CIDR for the VPC to create for the custom cloud environment")
    @arg("--display-name", help="User set display name for the custom cloud environment")
    def byoc__update(self) -> None:
        """Update an existing Bring Your Own Cloud configuration."""
        output = self.client.byoc_update(
            organization_id=self.args.organization_id,
            byoc_id=self.args.byoc_id,
            deployment_model=self.args.deployment_model,
            cloud_provider=self.args.cloud_provider,
            cloud_region=self.args.cloud_region,
            reserved_cidr=self.args.reserved_cidr,
            display_name=self.args.display_name,
            tags=None,
        )
        self.print_response(output)

    @arg("--organization-id", required=True, help="List BYOC cloud in this organization")
    def byoc__list(self) -> None:
        """List all Bring Your Own Cloud configurations in an organization."""
        output = self.client.byoc_list(organization_id=self.args.organization_id)
        self.print_response(output)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--aws-iam-role-arn", help="The IAM role that Aiven is authorized to assume to operate the cloud (AWS)")
    @arg(
        "--google-privilege-bearing-service-account-id",
        help="The privilege-bearing service account that Aiven is authorized to impersonate to operate the cloud (Google)",
    )
    def byoc__provision(self) -> None:
        """Provision resources for a Bring Your Own Cloud cloud."""
        if self.args.aws_iam_role_arn and self.args.google_privilege_bearing_service_account_id:
            raise argx.UserError(
                "--aws-iam-role-arn and --google-privilege-bearing-service-account-id are mutually exclusive."
            )
        output = self.client.byoc_provision(
            organization_id=self.args.organization_id,
            byoc_id=self.args.byoc_id,
            aws_iam_role_arn=self.args.aws_iam_role_arn,
            google_privilege_bearing_service_account_id=self.args.google_privilege_bearing_service_account_id,
        )
        self.print_response(output)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    def byoc__delete(self) -> None:
        """Delete a Bring Your Own Cloud cloud."""
        output = self.client.byoc_delete(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id)
        self.print_response(output)

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    def byoc__template__terraform__get_template(self) -> None:
        """Download Terraform template for provisioning a BYOC cloud."""
        print(self.client.byoc_terraform_get_template(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id))

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    def byoc__template__terraform__get_vars(self) -> None:
        """Download Terraform veriables for provisioning BYOC cloud."""
        print(self.client.byoc_terraform_get_vars(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id))

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    def byoc__cloud__permissions__get(self) -> None:
        """Get account and project permissions for a BYOC cloud."""
        print(self.client.byoc_permissions_get(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id))

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--account", nargs="*", help="Identifiers of accounts to give access to the BYOC cloud")
    @arg("--project", nargs="*", help="Names of project to give access to the BYOC cloud ")
    def byoc__cloud__permissions__set(self) -> None:
        """Set account and project permissions for a BYOC cloud, replacing the current set of permissions."""
        print(
            self.client.byoc_permissions_set(
                organization_id=self.args.organization_id,
                byoc_id=self.args.byoc_id,
                accounts=self.args.account or [],
                projects=self.args.project or [],
            )
        )

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--account", nargs="*", help="Identifier of an account to grant access to use the BYOC cloud")
    @arg("--project", nargs="*", help="Name of a projects to grant access to use the BYOC cloud")
    def byoc__cloud__permissions__add(self) -> None:
        """Update BYOC cloud permissions, adding access for accounts and/or projects."""
        permissions = self.client.byoc_permissions_get(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id)
        new_accounts = list(set(permissions["accounts"]) | set(self.args.account or []))
        new_projects = list(set(permissions["projects"]) | set(self.args.project or []))
        print(
            self.client.byoc_permissions_set(
                organization_id=self.args.organization_id,
                byoc_id=self.args.byoc_id,
                accounts=new_accounts,
                projects=new_projects,
            )
        )

    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--account", nargs="*", help="Identifier of an account to remove access to use the BYOC cloud")
    @arg("--project", nargs="*", help="Name of a projects to remove access to use the BYOC cloud")
    def byoc__cloud__permissions__remove(self) -> None:
        """Update BYOC cloud permissions, removing access from accounts and/or projects."""
        permissions = self.client.byoc_permissions_get(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id)
        new_accounts = list(set(permissions["accounts"]) - set(self.args.account or []))
        new_projects = list(set(permissions["projects"]) - set(self.args.project or []))
        print(
            self.client.byoc_permissions_set(
                organization_id=self.args.organization_id,
                byoc_id=self.args.byoc_id,
                accounts=new_accounts,
                projects=new_projects,
            )
        )

    @staticmethod
    def add_prefix_to_keys(prefix: str, tags: Mapping[str, S]) -> Mapping[str, S]:
        return {f"{prefix}{k}": v for (k, v) in tags.items()}

    @staticmethod
    def remove_prefix_from_keys(prefix: str, tags: Mapping[str, str]) -> Mapping[str, str]:
        return {(k.partition(prefix)[-1] if k.startswith(prefix) else k): v for (k, v) in tags.items()}

    @arg.json
    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    def byoc__tags__list(self) -> None:
        """List BYOC tags"""
        tags = self.client.list_byoc_tags(organization_id=self.args.organization_id, byoc_id=self.args.byoc_id)
        # Remove the "byoc_resource_tag:" prefix from BYOC tag keys to print them as expected by the end user.
        self._print_tags({"tags": self.remove_prefix_from_keys("byoc_resource_tag:", tags.get("tags", {}))})

    @arg.json
    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--add-tag", help="Add a new tag (key=value)", action="append", default=[])
    @arg("--remove-tag", help="Remove the named tag", action="append", default=[])
    def byoc__tags__update(self) -> None:
        """Add or remove BYOC tags"""
        response = self.client.update_byoc_tags(
            organization_id=self.args.organization_id,
            byoc_id=self.args.byoc_id,
            # Add the "byoc_resource_tag:" prefix to BYOC tag keys to make them cascade to the Bastion service.
            tag_updates=self.add_prefix_to_keys("byoc_resource_tag:", self._tag_update_body_from_args()),
        )
        print(response["message"])

    @arg.json
    @arg("--organization-id", required=True, help="Identifier of the organization of the custom cloud environment")
    @arg("--byoc-id", required=True, help="Identifier of the custom cloud environment that defines the BYOC cloud")
    @arg("--tag", help="Tag for service (key=value)", action="append", default=[])
    def byoc__tags__replace(self) -> None:
        """Replace BYOC tags, deleting any old ones first"""
        response = self.client.replace_byoc_tags(
            organization_id=self.args.organization_id,
            byoc_id=self.args.byoc_id,
            # Add the "byoc_resource_tag:" prefix to BYOC tag keys to make them cascade to the Bastion service.
            tags=self.add_prefix_to_keys("byoc_resource_tag:", self._tag_replace_body_from_args()),
        )
        print(response["message"])

    @arg.json
    @arg.project
    @arg.service_name
    @arg("--private-key-file", help="Filepath for the private key", required=True)
    def service__alloydbomni__google_cloud_private_key__set(self) -> None:
        """Set private key for AlloyDB Ommi AI model integration"""
        project_name = self.get_project()
        with open(self.args.private_key_file) as fp:
            private_key = fp.read()
        result = self.client.alloydbomni_google_cloud_private_key_set(
            project=project_name, service=self.args.service_name, private_key=private_key
        )
        output = []
        if result.get("client_email"):
            output.append(
                {
                    "client_email": result.get("client_email"),
                    "private_key_id": result.get("private_key_id"),
                }
            )
        if not output and not self.args.json:
            print("No service account key has been set")
        else:
            layout = ["client_email", "private_key_id"]
            self.print_response(output, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    @arg.service_name
    def service__alloydbomni__google_cloud_private_key__show(self) -> None:
        """Show information on installed private key for AlloyDB Ommi AI model integration"""
        project_name = self.get_project()
        result = self.client.alloydbomni_google_cloud_private_key_show(project=project_name, service=self.args.service_name)
        output = []
        if result.get("client_email"):
            output.append(
                {
                    "client_email": result.get("client_email"),
                    "private_key_id": result.get("private_key_id"),
                }
            )
        if not output and not self.args.json:
            print("No service account key has been set")
        else:
            layout = ["client_email", "private_key_id"]
            self.print_response(output, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    @arg.service_name
    def service__alloydbomni__google_cloud_private_key__delete(self) -> None:
        """Delete private key installed for AlloyDB Ommi AI model integration"""
        project_name = self.get_project()
        result = self.client.alloydbomni_google_cloud_private_key_delete(
            project=project_name, service=self.args.service_name
        )
        output = []
        if result.get("client_email"):
            output.append(
                {
                    "client_email": result.get("client_email"),
                    "private_key_id": result.get("private_key_id"),
                }
            )
        if not output and not self.args.json:
            print("Service account key has been removed")
        else:
            layout = ["client_email", "private_key_id"]
            self.print_response(output, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg(
        "--operation",
        help="Operation that is being allowed or denied.",
        required=True,
        choices=[
            "Describe",
            "DescribeConfigs",
            "Alter",
            "IdempotentWrite",
            "Read",
            "Delete",
            "Create",
            "ClusterAction",
            "All",
            "Write",
            "AlterConfigs",
            "CreateTokens",
            "DescribeTokens",
        ],
    )
    @arg(
        "--topic",
        help="Topic resource type to which ACL should be added",
    )
    @arg(
        "--group",
        help="Group resource type to which ACL should be added",
    )
    @arg(
        "--cluster",
        action="store_const",
        const="kafka-cluster",
        help="The ACL is applied to the cluster resource",
    )
    @arg(
        "--transactional-id",
        help="TransactionalId resource type to which ACL should be added",
    )
    @arg(
        "--resource-pattern-type",
        help="The type of the resource pattern",
        required=False,
        choices=["LITERAL", "PREFIXED"],
        default="LITERAL",
    )
    @arg(
        "--deny",
        help="Create a DENY rule (default is ALLOW)",
        action="store_true",
    )
    @arg(
        "--host",
        help="The host for the ACLs, a value of '*' matches all hosts",
        required=False,
        default="*",
    )
    @arg(
        "--principal",
        help="The principal for the ACLs, must be in the form principalType:name",
        required=True,
    )
    def service__kafka_acl_add(self) -> None:
        """Add a Kafka-native ACL entry"""
        mutually_exclusive_args = [
            self.args.topic,
            self.args.group,
            self.args.cluster,
            self.args.transactional_id,
        ]
        count = len(list(filter(lambda x: x is not None, mutually_exclusive_args)))
        if count == 0:
            raise argx.UserError("At least one of --topic --group --cluster --transactional-id must be specified")
        if count > 1:
            raise argx.UserError("Arguments --topic --group --cluster --transactional-id are mutually exclusive")
        if self.args.topic is not None:
            resource_name = self.args.topic
            resource_type = "Topic"
        elif self.args.group is not None:
            resource_name = self.args.group
            resource_type = "Group"
        elif self.args.cluster is not None:
            resource_name = self.args.cluster
            resource_type = "Cluster"
        elif self.args.transactional_id is not None:
            resource_name = self.args.transactional_id
            resource_type = "TransactionalId"

        response = self.client.service_kafka_native_acl_add(
            project=self.get_project(),
            service=self.args.service_name,
            principal=self.args.principal,
            host=self.args.host,
            resource_name=resource_name,
            resource_type=resource_type,
            resource_pattern_type=self.args.resource_pattern_type,
            operation=self.args.operation,
            permission_type="DENY" if self.args.deny else "ALLOW",
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg.json
    def service__kafka_acl_list(self) -> None:
        """List Kafka-native ACL entries"""
        response = self.client.service_kafka_native_acl_list(
            project=self.get_project(),
            service=self.args.service_name,
        )
        acls = response.get("kafka_acl", [])
        layout = [
            "id",
            "permission_type",
            "principal",
            "operation",
            "resource_type",
            "pattern_type",
            "resource_name",
            "host",
        ]
        if acls:
            self.print_response(acls, json=self.args.json, table_layout=layout)
        else:
            self.print_response([{k: "" for k in layout}], json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("acl_id", help="ID of the ACL entry to delete")
    def service__kafka_acl_delete(self) -> None:
        """Delete a Kafka-native ACL entry"""
        response = self.client.service_kafka_native_acl_delete(
            project=self.get_project(), service=self.args.service_name, acl_id=self.args.acl_id
        )
        print(response["message"])

    @arg.project
    @arg.service_name
    def service__opensearch__custom_repo_list(self) -> None:
        """Show custom repository information"""
        response = self.client.opensearch_custom_repo_list(
            project=self.get_project(),
            service=self.args.service_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    def service__opensearch__snapshot__in_progress(self) -> None:
        """Show custom repository snapshots in-progress"""
        response = self.client.opensearch_snapshot_in_progress(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    def service__opensearch__snapshot__list(self) -> None:
        """Show custom repository snapshots list"""
        response = self.client.opensearch_snapshot_list(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    @arg("snapshot_name", help="Snapshot name")
    def service__opensearch__snapshot__show(self) -> None:
        """Show custom repository snapshot info"""
        response = self.client.opensearch_snapshot_show(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
            snapshot_name=self.args.snapshot_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    @arg("snapshot_name", help="Snapshot name")
    def service__opensearch__snapshot__status(self) -> None:
        """Show custom repository snapshot status"""
        response = self.client.opensearch_snapshot_status(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
            snapshot_name=self.args.snapshot_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    @arg("snapshot_name", help="Snapshot name")
    @arg(
        "body",
        help="Request body json, see https://opensearch.org/docs/latest/api-reference/snapshots/create-snapshot/",
        default={},
    )
    def service__opensearch__snapshot__create(self) -> None:
        """Create a snapshot in custom repository"""
        response = self.client.opensearch_snapshot_create(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
            snapshot_name=self.args.snapshot_name,
            body=self.args.body,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    @arg("snapshot_name", help="Snapshot name")
    def service__opensearch__snapshot__delete(self) -> None:
        """Delete a snapshot from custom repository"""
        response = self.client.opensearch_snapshot_delete(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
            snapshot_name=self.args.snapshot_name,
        )
        self.print_response(response, json=True)

    @arg.project
    @arg.service_name
    @arg("repository_name", help="Custom Repository name")
    @arg("snapshot_name", help="Snapshot name")
    @arg(
        "body",
        help="Request body json, see https://opensearch.org/docs/latest/api-reference/snapshots/restore-snapshot/",
        default={},
    )
    def service__opensearch__snapshot__restore(self) -> None:
        """Restore a snapshot from custom repository"""
        response = self.client.opensearch_snapshot_restore(
            project=self.get_project(),
            service=self.args.service_name,
            repository_name=self.args.repository_name,
            snapshot_name=self.args.snapshot_name,
            body=self.args.body,
        )
        self.print_response(response, json=True)


if __name__ == "__main__":
    AivenCLI().main()
