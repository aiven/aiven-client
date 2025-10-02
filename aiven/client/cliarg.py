# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from .argx import arg, CommandLineTool, UserError
from functools import wraps
from typing import Any, Callable, TypeVar

import json as jsonlib
import os

__all__ = [
    "arg",
    "get_json_config",
    "json_path_or_string",
    "user_config_json",
]


def get_json_config(path_or_string: str) -> dict[str, Any]:
    # If parameter is empty, return an empty dict
    if not path_or_string:
        return {}
    if path_or_string.startswith("@"):
        filepath = path_or_string[1:]
        with open(filepath, encoding="utf-8") as config_file:
            return jsonlib.load(config_file)

    return jsonlib.loads(path_or_string)


T = TypeVar("T")


def json_path_or_string(param_name: str) -> Callable[[Callable[[CommandLineTool], T]], Callable[[CommandLineTool], T]]:
    def wrapper(fun: Callable[[CommandLineTool], T]) -> Callable[[CommandLineTool], T]:
        arg(
            param_name,
            help="JSON string or path (preceded by '@') to a JSON configuration file",
        )(fun)

        @wraps(fun)
        def wrapped(self: CommandLineTool) -> T:
            setattr(
                self.args,
                param_name,
                get_json_config(getattr(self.args, param_name, "")),
            )
            return fun(self)

        return wrapped

    return wrapper


def user_config_json() -> Callable[[Callable[[CommandLineTool], T]], Callable[[CommandLineTool], T]]:
    """User config that accepts arbitrary JSON"""

    def wrapper(fun: Callable[[CommandLineTool], T]) -> Callable[[CommandLineTool], T]:
        arg(
            "--user-config-json",
            default=None,
            dest="user_config_json",
            help="JSON string or path (preceded by '@') to a JSON configuration file",
        )(fun)

        @wraps(fun)
        def wrapped(self: CommandLineTool) -> T:
            assert self.args is not None
            if "user_config" in self.args and (self.args.user_config_json and self.args.user_config):
                raise UserError("-c (user config) and --user-config-json parameters can not be used at the same time")
            try:
                setattr(
                    self.args,
                    "user_config_json",
                    get_json_config(self.args.user_config_json),
                )
            except jsonlib.decoder.JSONDecodeError as err:
                raise UserError(f"Invalid user_config_json: {err!s}") from err
            return fun(self)

        return wrapped

    return wrapper


arg.account_id = arg("account_id", help="Account identifier")
arg.billing_address = arg("--billing-address", help="Physical billing address for invoices")
arg.billing_currency = arg("--billing-currency", help="Currency for charges")
arg.billing_extra_text = arg(
    "--billing-extra-text",
    help="Extra text to include in invoices (e.g. cost center id)",
)
arg.billing_group = arg("id", help="Billing group ID")
arg.card_id = arg("--card-id", help="Card ID")
arg.cloud = arg("--cloud", help="Cloud to use (see 'cloud list' command)")
arg.cloud_mandatory = arg("--cloud", help="Cloud to use (see 'cloud list' command)", required=True)
arg.config_cmdline = arg(
    "-c",
    dest="config_cmdline",
    metavar="KEY=VALUE",
    action="append",
    default=[],
    help="Additional configuration option in the form name=value",
)
arg.config_file = arg(
    "-f",
    dest="config_file",
    metavar="KEY=VALUE",
    action="append",
    default=[],
    help="Additional configuration option whose value is loaded from file in the form name=filename",
)
arg.country_code = arg("--country-code", help="Billing country code")
arg.disk_space_mb = arg(
    "--disk-space-gib", dest="disk_space_mb", type=lambda value: int(value) * 1024, help="Disk space for data storage (GiB)"
)
arg.email = arg("email", help="User email address")
arg.force = arg(
    "-f",
    "--force",
    help="Force action without interactive confirmation",
    action="store_true",
    default=False,
)
arg.group_id_positional = arg("group_id", help="Organization user group identifier")
arg.index_name = arg("index_name", help="Index name")
arg.json = arg("--json", help="Raw json output", action="store_true", default=False)
arg.min_insync_replicas = arg(
    "--min-insync-replicas",
    type=int,
    help="Minimum required nodes In Sync Replicas (ISR) to produce to a partition (default: 1)",
)
arg.organization_id = arg("--organization-id", required=True, help="Organization identifier")
arg.organization_id_positional = arg("organization_id", help="Organization identifier")
arg.parent_id = arg("--parent-id", help="Organization or account identifier")
arg.parent_id_mandatory = arg("--parent-id", required=True, help="Organization or account identifier")
arg.partitions = arg("--partitions", type=int, required=True, help="Number of partitions")
arg.project = arg(
    "--project",
    help="Project name to use, default %(default)r",
    default=os.environ.get("AIVEN_PROJECT"),
)
arg.replication = arg("--replication", type=int, required=True, help="Replication factor")
arg.retention = arg(
    "--retention", type=int, help="Retention period in hours, superseded by --retention-ms (default: unlimited)"
)
arg.retention_ms = arg("--retention-ms", type=int, help="Retention period in milliseconds (default: unlimited)")
arg.retention_bytes = arg("--retention-bytes", type=int, help="Retention limit in bytes (default: unlimited)")
arg.remote_storage_enable = arg("--remote-storage-enable", help="Enable tiered storage", action="store_true")
arg.remote_storage_disable = arg("--remote-storage-disable", help="Disable tiered storage", action="store_true")
arg.local_retention_ms = arg(
    "--local-retention-ms",
    type=int,
    help="Local retention period in milliseconds in case of tiered storage (default: equals to total retention.ms)",
)
arg.local_retention_bytes = arg(
    "--local-retention-bytes",
    type=int,
    help="Local retention limit in bytes in case of tiered storage (default: equals to total retention.bytes)",
)
arg.diskless_enable = arg("--diskless-enable", help="Enable diskless", action="store_true")
arg.diskless_disable = arg("--diskless-disable", help="Disable diskless", action="store_true")
arg.tag = arg(
    "--tag", dest="topic_option_tag", metavar="KEY[=VALUE]", action="append", help="Tag to add into topic metadata"
)
arg.tagupdate = arg(
    "--tag",
    dest="topic_option_tag",
    metavar="KEY[=VALUE]",
    action="append",
    help="Tag to add or replace into topic metadata",
)
arg.untag = arg(
    "--untag", dest="topic_option_untag", metavar="KEY", action="append", help="Tag to delete from topic metadata"
)
arg.service_name = arg("service_name", help="Service name")
arg.service_name_mandatory = arg("service_name", help="Service name", required=True)
arg.service_type = arg("-t", "--service-type", help="Type of service (see 'service types')")
arg.static_ip_id = arg("static_ip_id", help="Static IP address ID")
arg.ns_name = arg("ns_name", help="Namespace name")
arg.ns_type = arg("--ns-type", help="Namespace type ('aggregated' or 'unaggregated')", required=True)
arg.ns_retention_mandatory = arg(
    "--ns-retention", help="Namespace retention period (written like 30m/25h etc)", required=True
)
arg.ns_retention = arg("--ns-retention", help="Namespace retention period (written like 30m/25h etc)", required=False)
arg.ns_resolution = arg("--ns-resolution", help="Namespace resolution (written like 30m/25h etc)")
arg.ns_blocksize_dur = arg("--ns-blocksize-dur", help="Namespace block size duration (written like 30m/25h etc)")
arg.ns_block_data_expiry_dur = arg(
    "--ns-block-data-expiry-dur", help="Namespace block size duration (written like 30m/25h etc)"
)
arg.ns_buffer_future_dur = arg("--ns-buffer-future-dur", help="Namespace block size duration (written like 30m/25h etc)")
arg.ns_buffer_past_dur = arg("--ns-buffer-past-dur", help="Namespace block size duration (written like 30m/25h etc)")
arg.ns_writes_to_commitlog = arg("--ns-writes-to-commitlog", help="Namespace writes to commit log")
arg.team_name = arg("--team-name", help="Team  name", required=True)
arg.team_id = arg("--team-id", help="Team identifier", required=True)
arg.timeout = arg("--timeout", type=int, help="Wait for up to N seconds (default: infinite)")
arg.topic = arg("topic", help="Topic name")
arg.user_config = arg(
    "-c",
    dest="user_config",
    metavar="KEY=VALUE",
    action="append",
    default=[],
    help="Apply a configuration setting. See 'avn service types -v' for available values.",
)
arg.user_config_json = user_config_json
arg.user_id = arg("--user-id", help="User identifier", required=True)
arg.user_option_remove = arg(
    "--remove-option",
    dest="user_option_remove",
    action="append",
    default=[],
    help="Remove a configuration setting. See 'avn service types -v' for available settings.",
)
arg.vat_id = arg("--vat-id", help="VAT ID of an EU VAT area business")
arg.verbose = arg("-v", "--verbose", help="Verbose output", action="store_true", default=False)
arg.connector_name = arg("connector", help="Connector name")
arg.json_path_or_string = json_path_or_string
arg.subject = arg("--subject", required=True, help="Subject name")
arg.version_id = arg("--version-id", required=True, help="Subject version")
arg.compatibility = arg(
    "--compatibility",
    required=True,
    choices=["BACKWARD", "FORWARD", "FULL", "NONE"],
    help="Choose a compatibility level for the subject",
)
arg.schema = arg("--schema", required=True, help="Schema string quote escaped")

arg.source_cluster = arg("-s", "--source-cluster", required=True, help="Source cluster alias")
arg.target_cluster = arg("-t", "--target-cluster", required=True, help="Target cluster alias")

arg.billing_email = arg("--billing-email", action="append", help="Billing email address")
arg.tech_email = arg("--tech-email", action="append", help="Tech email address")

arg.flink_application_id = arg("--application-id", required=True, help="Flink application id")
arg.flink_application_version_id = arg("--application-version-id", required=True, help="Flink application version id")
arg.flink_deployment_id = arg("--deployment-id", required=True, help="Flink deployment id")
