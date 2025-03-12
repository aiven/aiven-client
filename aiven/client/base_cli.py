# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from . import argx, client
from aiven.client import AivenClient, envdefault
from aiven.client.base_client import Tag
from argparse import ArgumentParser
from ast import literal_eval
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional, Protocol, TypeVar

import getpass
import os
import re

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


class AivenBaseCLI(argx.CommandLineTool):
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

    def get_project(self, raise_if_none: bool = True) -> str:
        """Return project given as cmdline argument or the default project from config file"""
        if getattr(self.args, "project", None) and self.args.project:
            return self.args.project
        default_project = self.config.get("default_project", "")
        if raise_if_none and not default_project:
            raise argx.UserError(
                "Specify project: use --project in the command line or the default_project item in the config file."
            )
        return default_project
