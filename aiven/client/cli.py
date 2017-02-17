# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import print_function, unicode_literals
from . import argx, client
from aiven.client import envdefault
from aiven.client.cliarg import arg
from decimal import Decimal
import errno
import getpass
import json as jsonlib
import os
import requests
import time


PLUGINS = []


try:
    from aiven.admin import plugin as adminplugin  # pylint: disable=import-error,no-name-in-module
    PLUGINS.append(adminplugin)
except ImportError:
    pass

try:
    raw_input_func = raw_input  # pylint: disable=undefined-variable
except NameError:
    # python 3.x
    raw_input_func = input


def convert_str_to_value(schema, str_value):
    if "string" in schema["type"]:
        return str_value
    elif "integer" in schema["type"]:
        return int(str_value, 0)  # automatically convert from '123', '0x123', '0o644', etc.
    elif "number" in schema["type"]:
        return float(str_value)
    elif "boolean" in schema["type"]:
        values = {
            "1": True,
            "0": False,
            "true": True,
            "false": False,
        }
        try:
            return values[str_value]
        except KeyError:
            raise argx.UserError("Invalid boolean value {!r}: expected one of {}"
                                 .format(str_value, ", ".join(values)))
    elif "array" in schema["type"]:
        return [convert_str_to_value(schema["items"], val) for val in str_value.split(",")]
    else:
        raise argx.UserError("Supported for option value type(s) {!r} is unimplemented".format(schema["type"]))


def no_auth(fun):
    fun.no_auth = True
    return fun


def optional_auth(fun):
    fun.optional_auth = True
    return fun


class AivenCLI(argx.CommandLineTool):
    def __init__(self):
        argx.CommandLineTool.__init__(self, "avn")
        self.client = None
        for plugin in PLUGINS:
            plugincli = plugin.ClientPlugin()
            self.extend_commands(plugincli)

    def add_args(self, parser):
        parser.add_argument("--auth-ca", help="CA certificate to use [AIVEN_CA_CERT], default %(default)r",
                            default=envdefault.AIVEN_CA_CERT, metavar="FILE")
        parser.add_argument("--auth-token",
                            help="Client auth token to use [AIVEN_AUTH_TOKEN], [AIVEN_CREDENTIALS_FILE]",
                            default=envdefault.AIVEN_AUTH_TOKEN)
        parser.add_argument("--show-http", help="Show HTTP requests and responses", action="store_true")
        parser.add_argument("--url", help="Server base url default %(default)r",
                            default=envdefault.AIVEN_WEB_URL or "https://api.aiven.io")

    def enter_password(self, prompt, var="AIVEN_PASSWORD", confirm=False):
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

    def get_project(self):
        """Return project given as cmdline argument or the default project from config file"""
        if getattr(self.args, "project", None) and self.args.project:
            return self.args.project
        return self.config.get("default_project")

    @no_auth
    @arg("email", nargs="?", help="User email address")
    def user_login(self):
        """Login as a user"""
        email = self.args.email
        if not email:
            email = raw_input_func("Username (email): ")

        password = self.enter_password("{}'s Aiven password: ".format(email))
        result = self.client.authenticate_user(email=email, password=password)
        self._write_auth_token_file(token=result["token"], email=email)

        # ensure that there is a working default project
        auth_token = self._get_auth_token()
        if auth_token:
            self.client.set_auth_token(auth_token)

        project = self.get_project()
        projects = self.client.get_projects()
        if project and any(p["project_name"] == project for p in projects):
            # default project exists
            return

        if projects:
            default_project = projects[0]["project_name"]
            self.config["default_project"] = default_project
            self.config.save()
            self.log.info("Default project set as '%s' (change with 'avn project switch <project>')", default_project)
        else:
            self.log.info("No projects exists. You should probably create one with 'avn project create <name>'")

    @arg.verbose
    def user_tokens_expire(self):
        """Expire all authorization tokens"""
        message = self.client.expire_user_tokens()["message"]
        print(message)

    @arg("--format", help="Format string for output, e.g. '{filename} {size}'")
    @arg.json
    @arg.project
    def data_list(self):
        """List project data files"""
        files = self.client.list_data(project=self.get_project())["files"]
        layout = ["filename", "size", "create_time"]

        self.print_response(files, format=self.args.format, json=self.args.json,
                            table_layout=layout)

    @arg.project
    @arg("filename", help="Name of the file to download", nargs="+")
    def data_download(self):
        """Download a data file from a project"""
        for filename in self.args.filename:
            result = self.client.download_data(project=self.get_project(), filename=filename)
            print(result)

    @arg.project
    @arg("filename", help="Name of the file to upload", nargs="+")
    def data_upload(self):
        """Upload a data file to a project"""
        for filename in self.args.filename:
            result = self.client.upload_data(project=self.get_project(), filename=filename)
            print(result)

    @arg.project
    @arg("filename", help="Name of the file to delete", nargs="+")
    def data_delete(self):
        """Delete a data file from a project"""
        for filename in self.args.filename:
            result = self.client.delete_data(project=self.get_project(), filename=filename)
            print(result)

    def _show_logs(self, offset):
        msgs = self.client.get_logs(
            project=self.get_project(),
            limit=self.args.limit,
            offset=offset)

        if self.args.json:
            print(jsonlib.dumps(msgs["logs"], indent=4, sort_keys=True))
        else:
            for log_msg in msgs["logs"]:
                print("{time:<27}  {msg}".format(**log_msg))
        return msgs["offset"]

    @arg.project
    @arg.json
    @arg("-n", "--limit", type=int, default=100, help="Get up to N rows of logs")
    @arg("-f", "--follow", action="store_true", default=False)
    def logs(self):
        """View project logs"""
        previous_offset = -self.args.limit
        while True:
            new_offset = self._show_logs(previous_offset)
            if not self.args.follow:
                break
            if previous_offset == new_offset:
                # No new msgs, sleep for a while
                time.sleep(10.0)
            previous_offset = new_offset

    @arg.project
    @arg.json
    @arg("-n", "--limit", type=int, default=100, help="Get up to N rows of logs")
    def events(self):
        """View project event logs"""
        events = self.client.get_events(
            project=self.get_project(),
            limit=self.args.limit)

        if self.args.json:
            return print(jsonlib.dumps(events, indent=4, sort_keys=True))

        for msg in events:
            if not msg["service_name"]:
                msg["service_name"] = ""

        layout = ["time", "actor", "event_type", "service_name", "event_desc"]
        self.print_response(events, json=self.args.json, table_layout=layout)

    @optional_auth
    @arg.project
    @arg.json
    def cloud_list(self):
        """List cloud types"""
        project = self.get_project()
        if project and not self.client.auth_token:
            raise argx.UserError("authentication is required to list clouds for a specific project")
        self.print_response(self.client.get_clouds(project=project), json=self.args.json)

    def collect_user_config_options(self, obj_def, prefix=""):
        opts = {}
        for prop, spec in sorted(obj_def.get("properties", {}).items()):
            full_name = prop if not prefix else (prefix + "." + prop)
            if spec["type"] == "object":
                opts.update(self.collect_user_config_options(spec, prefix=full_name))
            else:
                opts[full_name] = spec
        for spec in sorted(obj_def.get("patternProperties", {}).values()):
            full_name = "KEY" if not prefix else (prefix + ".KEY")
            if spec["type"] == "object":
                opts.update(self.collect_user_config_options(spec, prefix=full_name))
            else:
                opts[full_name] = spec
        return opts

    @staticmethod
    def describe_plan(plan):
        """Describe a plan based on their specs as published in the api, returning strings like:
        "Basic-0 (4 CPU, 123 MB RAM) "
        "Basic-1 (4 CPU, 1 GB RAM, 9 GB disk) "
        "Dual-1 (4 CPU, 1 GB RAM, 9 GB disk) high availability pair"
        "Quad-2 (4 CPU, 2 GB RAM, 9 GB disk) 4-node high availability set"
        """
        if plan["node_memory_mb"] < 1024:
            ram_amount = "{} MB".format(plan["node_memory_mb"])
        else:
            ram_amount = "{:.0f} GB".format(plan["node_memory_mb"] / 1024.0)

        if plan["disk_space_mb"]:
            disk_desc = ", {:.0f} GB disk".format(plan["disk_space_mb"] / 1024.0)
        else:
            disk_desc = ""

        if plan["node_count"] == 2:
            plan_qual = " high availability pair"
        elif plan["node_count"] > 2:
            plan_qual = " {}-node high availability set".format(plan["node_count"])
        else:
            plan_qual = ""

        return "{name} ({cpu_count} CPU, {ram_amount} RAM{disk_desc}){qual}".format(
            name=plan["service_plan"].title(),
            cpu_count=plan["node_cpu_count"],
            ram_amount=ram_amount,
            disk_desc=disk_desc,
            qual=plan_qual,
        )

    @optional_auth
    @arg.project
    @arg.json
    def service_plans(self):
        """List service plans"""
        project = self.get_project()
        if project and not self.client.auth_token:
            raise argx.UserError("authentication is required to list service plans for a specific project")

        service_types = self.client.get_service_types(project=project)
        if self.args.json:
            return print(jsonlib.dumps(service_types, indent=4, sort_keys=True))

        output = []
        for service_type, prop in service_types.items():
            entry = prop.copy()
            entry["service_type"] = service_type
            output.append(entry)

        dformat = Decimal("0.000")

        for info in sorted(output, key=lambda s: s["description"]):
            print("{} Plans:\n".format(info["description"]))
            for plan in info["service_plans"]:
                args = "{}:{}".format(plan["service_type"], plan["service_plan"])
                price_dec = Decimal(plan["price_usd"])
                price = "${}/h".format(price_dec.quantize(dformat))
                print("    {:<28} {:>10}  {}".format(args, price, self.describe_plan(plan)))

            if not info["service_plans"]:
                print("    (no plans available)")

            print()

    @arg.project
    @arg.json
    @arg.verbose
    def service_types(self):
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
                        if isinstance(default, list):
                            default = ",".join(default)

                        default_desc = "(default={!r})".format(default) if default is not None else ""
                        types = spec["type"]
                        if not isinstance(types, list):
                            types = [types]
                        type_str = " or ".join(t for t in types if t != "null")
                        print("  -c {name}=<{type}>  {default}\n"
                              "     => {title}"
                              .format(name=name, type=type_str,
                                      default=default_desc, title=spec["title"]))

    SERVICE_LAYOUT = [["service_name", "service_type", "state", "cloud_name", "plan",
                       "group_list", "create_time", "update_time"]]
    EXT_SERVICE_LAYOUT = ["service_uri", "user_config.*", "databases", "users"]

    @arg.project
    @arg("name", nargs="*", default=[], help="Service name")
    @arg.service_type
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service_list(self):
        """List services"""
        services = self.client.get_services(project=self.get_project())
        if self.args.service_type is not None:
            services = [s for s in services if s["service_type"] == self.args.service_type]
        if self.args.name:
            services = [s for s in services if s["service_name"] in self.args.name]

        layout = self.SERVICE_LAYOUT[:]
        if self.args.verbose:
            layout.extend(self.EXT_SERVICE_LAYOUT)

        self.print_response(services, format=self.args.format, json=self.args.json,
                            table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service_get(self):
        """Show a single service"""
        service = self.client.get_service(project=self.get_project(), service=self.args.name)

        layout = self.SERVICE_LAYOUT[:]
        if self.args.verbose:
            layout.extend(self.EXT_SERVICE_LAYOUT)

        self.print_response(service, format=self.args.format, json=self.args.json,
                            table_layout=layout, single_item=True)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{service_name} {service_uri}'")
    @arg.verbose
    @arg.json
    def service_credentials_reset(self):
        """Reset service credentials"""
        service = self.client.reset_service_credentials(project=self.get_project(), service=self.args.name)
        layout = [["service_name", "service_type", "state", "cloud_name", "plan",
                   "group_list", "create_time", "update_time"]]
        if self.args.verbose:
            layout.extend(["service_uri", "user_config.*"])
        self.print_response([service], format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--period", help="Metrics period", default="hour", choices=["hour", "day", "week", "month", "year"])
    def service_metrics(self):
        """Get service metrics"""
        metrics = self.client.get_service_metrics(project=self.get_project(), service=self.args.name,
                                                  period=self.args.period)
        print(jsonlib.dumps(metrics, indent=2, sort_keys=True))

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg("--dbname", help="Service database name", required=True)
    @arg("--username", help="Service username", required=True)
    @arg("--pool-size", type=int, help="Connection pool size")
    @arg("--pool-mode", help="Connection pool mode")
    @arg.json
    def service_connection_pool_create(self):
        """Create a connection pool for a given PostgreSQL service"""
        self.client.create_service_connection_pool(
            project=self.get_project(),
            service=self.args.name,
            pool_name=self.args.pool_name,
            dbname=self.args.dbname,
            username=self.args.username,
            pool_size=self.args.pool_size,
            pool_mode=self.args.pool_mode)

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg("--dbname", help="Service database name")
    @arg("--username", help="Service username")
    @arg("--pool-size", type=int, help="Connection pool size")
    @arg("--pool-mode", help="Connection pool mode")
    @arg.json
    def service_connection_pool_update(self):
        """Update a connection pool for a given PostgreSQL service"""
        self.client.update_service_connection_pool(
            project=self.get_project(),
            service=self.args.name,
            pool_name=self.args.pool_name,
            dbname=self.args.dbname,
            username=self.args.username,
            pool_size=self.args.pool_size,
            pool_mode=self.args.pool_mode)

    @arg.project
    @arg.service_name
    @arg("--pool-name", help="Connection pool name", required=True)
    @arg.json
    def service_connection_pool_delete(self):
        """Delete a connection pool from a given service"""
        self.client.delete_service_connection_pool(project=self.get_project(), service=self.args.name,
                                                   pool_name=self.args.pool_name)

    @arg.project
    @arg.service_name
    @arg.verbose
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.json
    def service_connection_pool_list(self):
        """List PGBouncer pools for a service """
        service = self.client.get_service(project=self.get_project(), service=self.args.name)
        layout = ["pool_name", "database", "username", "pool_mode", "pool_size"]
        if self.args.verbose:
            layout.append("connection_uri")
        self.print_response(service["connection_pools"], format=self.args.format, json=self.args.json,
                            table_layout=[layout])

    @arg.project
    @arg.service_name
    @arg("--dbname", help="Service database name", required=True)
    @arg("--lc-collate", help="Default PostgreSQL string sort order (LC_COLLATE) for the database")
    @arg("--lc-ctype", help="Default PostgreSQL character classification (LC_CTYPE) for the database")
    @arg.json
    def service_database_create(self):
        """Create a database within a given service"""
        self.client.create_service_database(project=self.get_project(), service=self.args.name,
                                            dbname=self.args.dbname, lc_ctype=self.args.lc_ctype,
                                            lc_collate=self.args.lc_collate)

    @arg.project
    @arg.service_name
    @arg("--dbname", help="Service database name", required=True)
    @arg.json
    def service_database_delete(self):
        """Delete a database within a given service"""
        self.client.delete_service_database(project=self.get_project(), service=self.args.name,
                                            dbname=self.args.dbname)

    @arg.project
    @arg.service_name
    def service_maintenance_start(self):
        """Start service maintenance updates"""
        response = self.client.start_service_maintenance(project=self.get_project(), service=self.args.name)
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg.json
    def service_user_create(self):
        """Create service user"""
        self.client.create_service_user(project=self.get_project(), service=self.args.name,
                                        username=self.args.username)

    @arg.project
    @arg.service_name
    @arg("--username", help="Service user username", required=True)
    @arg.json
    def service_user_delete(self):
        """Delete a service user"""
        self.client.delete_service_user(project=self.get_project(), service=self.args.name,
                                        username=self.args.username)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{username} {password}'")
    @arg.json
    def service_user_list(self):
        """List service users """
        service = self.client.get_service(project=self.get_project(), service=self.args.name)
        layout = [["username", "type"]]
        self.print_response(service["users"], format=self.args.format, json=self.args.json,
                            table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.json
    def service_database_list(self):
        """List service databases"""
        service = self.client.get_service(project=self.get_project(), service=self.args.name)
        db_list = [dict({"database": dbname}, **dbinfo) for dbname, dbinfo in service["databases"].items()]
        db_list.sort(key=lambda item: item["database"])
        if service["service_type"] == "pg":
            layout = [["database", "lc_ctype", "lc_collate"]]
        else:
            layout = [["database"]]
        self.print_response(db_list, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{calls} {total_time}'")
    @arg.verbose
    @arg.json
    def service_queries_reset(self):
        """Reset PostgreSQL service query statistics"""
        queries = self.client.reset_pg_service_query_stats(project=self.get_project(), service=self.args.name)
        self.print_response(queries, format=self.args.format, json=self.args.json)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{query} {backend_start}'")
    @arg.verbose
    @arg.json
    def service_current_queries(self):
        """List current PostgreSQL queries"""
        queries = self.client.get_pg_service_current_queries(project=self.get_project(), service=self.args.name)
        layout = [["pid", "query", "query_duration", "client_addr", "application_name"]]
        if self.args.verbose:
            layout.extend(["datid", "datname", "pid", "usesysid", "usename", "application_name", "client_addr",
                           "client_hostname", "client_port", "backend_start", "xact_start", "query_start",
                           "state_change", "waiting", "state", "backend_xid", "backend_xmin", "query",
                           "query_duration"])
        self.print_response(queries, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{calls} {total_time}'")
    @arg.verbose
    @arg.json
    def service_queries(self):
        """List PostgreSQL service query statistics"""
        queries = self.client.get_pg_service_query_stats(project=self.get_project(), service=self.args.name)
        layout = [["query", "max_time", "stddev_time", "min_time", "mean_time", "rows", "calls", "total_time"]]
        if self.args.verbose:
            layout.extend(["dbid", "userid", "queryid", "shared_blks_read", "local_blks_read", "local_blks_hit",
                           "local_blks_written", "local_blks_dirtied", "shared_blks_hit",
                           "shared_blks_dirtied", "shared_blks_written",
                           "blk_read_time", "blk_write_time", "temp_blks_read", "temp_blks_written"])
        self.print_response(queries, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service_index_list(self):
        """List Elasticsearch service indexes"""
        indexes = self.client.get_service_indexes(project=self.get_project(), service=self.args.name)
        layout = [["index_name", "number_of_shards", "number_of_replicas", "create_time"]]
        self.print_response(indexes, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.index_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service_index_delete(self):
        """Delete Elasticsearch service index"""
        self.client.delete_service_index(project=self.get_project(), service=self.args.name,
                                         index_name=self.args.index_name)

    @arg.project
    @arg.service_name
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    def service_topic_list(self):
        """List Kafka service topics"""
        service = self.client.get_service(project=self.get_project(), service=self.args.name)
        layout = [["topic_name", "partitions", "replication", "retention_hours", "state"]]
        self.print_response(service["topics"], format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.topic
    @arg("--format", help="Format string for output, e.g. '{name} {retention_hours}'")
    @arg.json
    @arg.verbose
    def service_topic_get(self):
        """Get Kafka service topic"""
        topic = self.client.get_service_topic(project=self.get_project(), service=self.args.name,
                                              topic=self.args.topic)
        layout = [["partition", "isr", "size", "earliest_offset", "latest_offset", "groups"]]
        for p in topic["partitions"]:
            p["groups"] = len(p["consumer_groups"])

        self.print_response(topic["partitions"], format=self.args.format, json=self.args.json, table_layout=layout)
        print()

        layout = [["partition", "consumer_group", "offset"]]
        cgroups = []
        for p in topic["partitions"]:
            for cg in p["consumer_groups"]:
                cgroups.append({
                    "partition": p["partition"],
                    "consumer_group": cg["group_name"],
                    "offset": cg["offset"],
                })

        if not cgroups:
            print("(No consumer groups)")
        else:
            self.print_response(cgroups, format=self.args.format, json=self.args.json, table_layout=layout)

    @arg.project
    @arg.service_name
    @arg.topic
    @arg.partitions
    @arg.replication
    @arg.retention
    def service_topic_create(self):
        """Create a Kafka topic"""
        response = self.client.create_service_topic(project=self.get_project(),
                                                    service=self.args.name,
                                                    topic=self.args.topic,
                                                    partitions=self.args.partitions,
                                                    replication=self.args.replication,
                                                    retention_hours=self.args.retention)
        print(response)

    @arg.project
    @arg.service_name
    @arg.topic
    @arg.partitions
    @arg.retention
    def service_topic_update(self):
        """Update a Kafka topic"""
        response = self.client.update_service_topic(project=self.get_project(),
                                                    service=self.args.name,
                                                    topic=self.args.topic,
                                                    partitions=self.args.partitions,
                                                    retention_hours=self.args.retention)
        print(response["message"])

    @arg.project
    @arg.service_name
    @arg.topic
    def service_topic_delete(self):
        """Delete a Kafka topic"""
        response = self.client.delete_service_topic(project=self.get_project(),
                                                    service=self.args.name,
                                                    topic=self.args.topic)
        print(response["message"])

    @arg.project
    @arg("service", nargs="+", help="Service to wait for")
    @arg.timeout
    def service_wait(self):
        """Wait service to reach the 'RUNNING' state"""
        start_time = time.time()
        report_interval = 30.0
        next_report = start_time + report_interval
        last = {}
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
                return

            if self.args.timeout is not None and (time.time() - start_time) > self.args.timeout:
                self.log.error("Timeout waiting for service(s) to start")
                return 1

            if time.time() >= next_report:
                next_report = time.time() + report_interval
                self.log.info("Waiting for services to start")

            time.sleep(3.0)

    @arg.project
    @arg.force
    @arg("name", help="Service name", nargs="+")
    def service_terminate(self):
        """Terminate service"""
        if not self.args.force and os.environ.get("AIVEN_FORCE") != "true":
            output = [
                "Please re-enter the service name(s) to confirm the service termination.",
                "This cannot be undone and all the data in the service will be lost!",
                "Re-entering service name(s) can be skipped with the --force option.",
            ]
            longest = max(len(line) for line in output)
            print("*" * longest)
            for line in output:
                print(line)
            print("*" * longest)

            for name in self.args.name:
                user_input = raw_input_func("Re-enter service name {!r} for immediate termination: ".format(name))
                if user_input != name:
                    raise argx.UserError("Not confirmed by user. Aborting termination.")

        for name in self.args.name:
            self.client.delete_service(project=self.get_project(), service=name)
            self.log.info("%s: terminated", name)

    def create_user_config(self, project, service_type, config_vars):
        """Convert a list of ["foo.bar='baz'"] to {"foo": {"bar": "baz"}}"""
        if not config_vars:
            return {}

        service_types = self.client.get_service_types(project=project)
        try:
            service_def = service_types[service_type]
        except KeyError:
            raise argx.UserError("Unknown service type {!r}, available options: {}".format(
                service_type, ", ".join(service_types)))

        options = self.collect_user_config_options(service_def["user_config_schema"])
        user_config = {}
        for key_value in self.args.user_config:
            try:
                key, value = key_value.split("=", 1)
            except ValueError:
                raise argx.UserError("Invalid config value: {!r}, expected '<KEY>[.<SUBKEY>]=<JSON_VALUE>'"
                                     .format(key_value))

            opt_schema = options.get(key)
            if not opt_schema:
                # Exact key not found, try generic one
                generic_key = ".".join(key.split(".")[:-1] + ["KEY"])
                opt_schema = options.get(generic_key)

            if not opt_schema:
                raise argx.UserError("Unsupported option {!r}, available options: {}"
                                     .format(key, ", ".join(options) or "none"))

            try:
                value = convert_str_to_value(opt_schema, value)
            except ValueError as ex:
                raise argx.UserError("Invalid value {!r}: {}".format(key_value, ex))

            conf = user_config
            parts = key.split(".")
            for part in parts[:-1]:
                conf.setdefault(part, {})
                conf = conf[part]

            conf[parts[-1]] = value

        return user_config

    @arg.project
    @arg.service_name
    @arg("--group-name", help="service group", default="default")
    @arg("-t", "--service-type", help="type of service (see 'service types')", required=True)
    @arg("-p", "--plan", help="subscription plan of service", required=False)
    @arg.cloud
    @arg("--no-fail-if-exists", action="store_true", default=False,
         help="do not fail if service already exists")
    @arg.user_config
    def service_create(self):
        """Create a service"""
        service_type_info = self.args.service_type.split(":")
        service_type = service_type_info[0]

        plan = None
        if len(service_type_info) == 2:
            plan = service_type_info[1]
        elif self.args.plan:
            plan = self.args.plan
        if not plan:
            raise argx.UserError("No subscription plan given")

        project = self.get_project()
        try:
            self.client.create_service(
                project=project,
                service=self.args.name,
                service_type=service_type,
                plan=plan,
                cloud=self.args.cloud,
                group_name=self.args.group_name,
                user_config=self.create_user_config(project, self.args.service_type, self.args.user_config))
        except client.Error as ex:
            print(ex.response)
            if not self.args.no_fail_if_exists or ex.response.status_code != 409:
                raise

            self.log.info("service '%s/%s' already exists", project, self.args.name)

    def _get_powered(self):
        if self.args.power_on and self.args.power_off:
            raise argx.UserError("Only one of --power-on or --power-off can be specified")
        elif self.args.power_on:
            return True
        elif self.args.power_off:
            return False
        else:
            return None

    @arg.project
    @arg.service_name
    @arg("--group-name", help="New service group")
    @arg.cloud
    @arg.user_config
    @arg("-p", "--plan", help="subscription plan of service", required=False)
    @arg("--power-on", action="store_true", default=False, help="Power-on the service")
    @arg("--power-off", action="store_true", default=False, help="Temporarily power-off the service")
    @arg("--maintenance-dow", help="automatic maintenance day of week",
         choices=["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "never"])
    @arg("--maintenance-time", help="automatic maintenance time of day (HH:MM:SS)")
    def service_update(self):
        """Update service settings"""
        powered = self._get_powered()
        project = self.get_project()
        service = self.client.get_service(project=project, service=self.args.name)
        plan = self.args.plan or service["plan"]
        user_config = self.create_user_config(project, service["service_type"], self.args.user_config)
        maintenance = {}
        if self.args.maintenance_dow:
            maintenance["dow"] = self.args.maintenance_dow
        if self.args.maintenance_time:
            maintenance["time"] = self.args.maintenance_time
        try:
            self.client.update_service(
                cloud=self.args.cloud,
                group_name=self.args.group_name,
                maintenance=maintenance or None,
                plan=plan,
                powered=powered,
                project=project,
                service=self.args.name,
                user_config=user_config,
            )
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Service '{}/{}' update failed".format(project, self.args.name))

    @arg("name", help="Project name")
    @arg.cloud
    def project_switch(self):
        """Switch the default project"""
        projects = self.client.get_projects()
        project_names = [p["project_name"] for p in projects]
        if self.args.name in project_names:
            self.config["default_project"] = self.args.name
            self.config.save()
            self.log.info("Set project %r as the default project", self.args.name)
        else:
            raise argx.UserError("Project {!r} does not exist, available projects: {}".format(
                self.args.name, ", ".join(project_names)))

    @arg("name", help="Project name")
    @arg.cloud
    def project_delete(self):
        """Delete a project"""
        self.client.delete_project(project=self.args.name)

    @arg.project
    @arg("name", help="Project alert endpoint name")
    @arg("--metadata", help="Metadata for alert endpoint")
    @arg("--slack-webhook-url", help="Slack Incoming Webhook URL")
    @arg("--slack-channel", help="Slack channel, for example '#aiven-alerts'")
    @arg.cloud
    def project_alert_endpoint_create(self):
        """Create project alert endpoint"""
        project_name = self.get_project()
        if self.args.metadata:
            metadata = jsonlib.loads(self.args.metadata)
        elif self.args.slack_webhook_url:
            metadata = {
                "endpoint_type": "slack",
                "slack_webhook_url": self.args.slack_webhook_url,
            }
        else:
            raise argx.UserError("Either --metadata or --slack-token is required")

        if self.args.slack_channel:
            metadata["slack_channel"] = self.args.slack_channel

        self.client.create_project_alert_endpoint(
            project=project_name,
            alert_endpoint_name=self.args.name,
            metadata=metadata)

    @arg.project
    @arg("name", help="Project alert endpoint name")
    @arg.cloud
    def project_alert_endpoint_delete(self):
        """Delete project alert endpoint"""
        project_name = self.get_project()
        self.client.delete_project_alert_endpoint(
            project=project_name,
            alert_endpoint_name=self.args.name)

    @arg.json
    @arg.project
    @arg.cloud
    def project_alert_endpoint_list(self):
        """List project alert endpoints"""
        project_name = self.get_project()
        alert_endpoints = self.client.get_project_alert_endpoints(
            project=project_name)
        if not self.args.json:
            for endpoint in alert_endpoints:
                endpoint["slack_channel"] = endpoint["metadata"].get("slack_channel", "(default)")
        self.print_response(alert_endpoints,
                            json=self.args.json,
                            table_layout=["endpoint_name", "endpoint_type", "create_time", "slack_channel"])

    @arg.project
    @arg.service_name
    @arg("--alert-name", help="Service alert name", required=True)
    @arg("--query", help="Elasticsearch search query to perform", required=True)
    @arg("--endpoints", metavar="ENDPOINT", nargs="*", help="Project alert target endpoints")
    @arg("--threshold", type=int, default=-1, help="Seach hits threshold value")
    @arg("--operator", help="Search hits comparison operator", choices=["=", ">", ">=", "<", "<="])
    @arg.cloud
    def service_alert_create(self):
        """Create service alert"""
        project_name = self.get_project()
        endpoints = self.args.endpoints
        if not endpoints:
            endpoints = [e["endpoint_name"] for e in self.client.get_project_alert_endpoints(project=project_name)]
            if len(endpoints) == 0:
                raise argx.UserError("No project alert endpoints defined")
            elif len(endpoints) > 1:
                raise argx.UserError("More than one alert endpoints exist, "
                                     "use --endpoints to choose one of: {}".format(", ".join(endpoints)))
            self.log.info("Using alert endpoint %r", endpoints[0])

        self.client.create_service_alert(
            project=project_name,
            service=self.args.name,
            alert_name=self.args.alert_name,
            alert_endpoints=endpoints,
            query=self.args.query,
            operator=self.args.operator,
            threshold=self.args.threshold)

    @arg.project
    @arg.service_name
    @arg("--alert-name", help="Service alert", required=True)
    @arg.cloud
    def service_alert_delete(self):
        """Delete service alert"""
        project_name = self.get_project()
        self.client.delete_service_alert(
            project=project_name,
            service=self.args.name,
            alert_name=self.args.alert_name)

    @arg.json
    @arg.project
    @arg.service_name
    @arg.cloud
    def service_alert_list(self):
        """List service alerts"""
        project_name = self.get_project()
        service_alerts = self.client.get_service_alerts(
            project=project_name, service=self.args.name)
        if not self.args.json:
            for alert in service_alerts:
                alert["query"] = alert["metadata"]["query"]
                alert["operator"] = alert["metadata"]["operator"]
                alert["threshold"] = alert["metadata"]["alert_threshold"]
                alert["endpoints"] = ",".join(alert["alert_endpoints"])
        self.print_response(
            service_alerts,
            json=self.args.json,
            table_layout=["alert_name", "create_time", "query", "operator", "threshold", "endpoints"])

    @classmethod
    def _project_credit_card(cls, project):
        card_info = project.get("card_info")
        if card_info:
            return "{}/{}".format(project["card_info"]["user_email"], project["card_info"]["card_id"])
        else:
            return "N/A"

    @arg("name", help="Project name")
    @arg.card_id
    @arg.cloud
    @arg("--no-fail-if-exists", action="store_true", default=False,
         help="Do not fail if project already exists")
    def project_create(self):
        """Create a project"""
        try:
            project = self.client.create_project(project=self.args.name,
                                                 card_id=self.args.card_id,
                                                 cloud=self.args.cloud)
        except client.Error as ex:
            if not self.args.no_fail_if_exists or ex.response.status_code != 409:
                raise

            self.log.info("Project '%s' already exists", self.args.name)

        self.config["default_project"] = self.args.name
        self.config.save()
        self.log.info("Created project %r (default cloud: %r, credit_card: %r) and set it as the default project",
                      self.args.name, project["default_cloud"], self._project_credit_card(project))

    @arg.json
    @arg.project
    def project_details(self):
        """Show project details"""
        project_name = self.get_project()
        project = self.client.get_project(project=project_name)
        project["credit_card"] = self._project_credit_card(project)
        self.print_response([project],
                            json=self.args.json,
                            table_layout=["project_name", "default_cloud", "credit_card"])

    @arg.json
    def project_list(self):
        """List projects"""
        projects = self.client.get_projects()
        for project in projects:
            project["credit_card"] = self._project_credit_card(project)
        self.print_response(projects,
                            json=self.args.json,
                            table_layout=["project_name", "default_cloud", "credit_card"])

    @arg.project
    @arg("--card-id", help="Card ID")
    @arg.cloud
    def project_update(self):
        """Update a project"""
        project_name = self.get_project()
        try:
            project = self.client.update_project(project=project_name,
                                                 card_id=self.args.card_id,
                                                 cloud=self.args.cloud)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' update failed".format(project_name))
        self.log.info("Updated project %r, default cloud: %r, credit card: %r",
                      project_name,
                      project["default_cloud"],
                      self._project_credit_card(project))

    @arg.project
    @arg("--target-filepath", help="Project CA filepath", required=True)
    def project_ca_get(self):
        """Get project CA certificate"""
        project_name = self.get_project()
        try:
            result = self.client.get_project_ca(project=project_name)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' CA get failed".format(project_name))
        with open(self.args.target_filepath, "w") as fp:
            fp.write(result["certificate"])

    @arg.project
    @arg("--cert-name", help="Project SSL certificate name", required=True)
    @arg("--target-cert-filepath", help="Project SSL certificate filepath", required=True)
    @arg("--target-key-filepath", help="Project SSL key filepath", required=True)
    def project_cert_create(self):
        """Create project certificate"""
        project_name = self.get_project()
        try:
            result = self.client.create_project_certificate(project=project_name, certname=self.args.cert_name)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' certificate {} create failed".format(project_name, self.args.cert_name))
        with open(self.args.target_cert_filepath, "w") as fp:
            fp.write(result["certificate"])
        with open(self.args.target_key_filepath, "w") as fp:
            fp.write(result["key"])

    @arg.json
    @arg.project
    def project_cert_list(self):
        """List project certificates"""
        project_name = self.get_project()
        try:
            result = self.client.list_project_certificates(project=project_name)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' certificate {} create failed".format(project_name, self.args.cert_name))
        layout = [["name", "create_time"]]
        self.print_response(result, json=self.args.json, table_layout=layout)

    @arg.project
    @arg("--cert-name", help="Project SSL certificate name", required=True)
    def project_cert_delete(self):
        """Delete project certificate"""
        project_name = self.get_project()
        try:
            self.client.delete_project_certificate(project=project_name, certname=self.args.cert_name)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' certificate {} delete failed".format(project_name, self.args.cert_name))

    @arg.project
    @arg.email
    def project_user_invite(self):
        """Invite a new user to the project"""
        project_name = self.get_project()
        try:
            self.client.invite_project_user(project=project_name, user_email=self.args.email)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project '{}' invite for {} failed".format(project_name, self.args.email))
        self.log.info("Invited %r into project %r", self.args.email, project_name)

    @arg.project
    @arg.email
    def project_user_remove(self):
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
    def project_user_list(self):
        """Project user list"""
        project_name = self.get_project()
        try:
            user_list = self.client.list_project_users(project=project_name)
            layout = [["user_email", "member_type", "create_time"]]
            self.print_response(user_list, json=self.args.json, table_layout=layout)
        except client.Error as ex:
            print(ex.response.text)
            raise argx.UserError("Project user listing for '{}' failed".format(project_name))

    @arg.email
    @arg("--real-name", help="User real name", required=True)
    def user_create(self):
        """Create a user"""
        password = self.enter_password("New aiven.io password for {}: ".format(self.args.email),
                                       var="AIVEN_NEW_PASSWORD", confirm=True)
        result = self.client.create_user(email=self.args.email,
                                         password=password,
                                         real_name=self.args.real_name)

        self._write_auth_token_file(token=result["token"], email=self.args.email)

    @arg.json
    def user_info(self):
        """Show current user info"""
        result = self.client.get_user_info()
        layout = [["user", "real_name", "state", "token_validity_begin", "projects"]]
        self.print_response([result], json=self.args.json, table_layout=layout)

    def _write_auth_token_file(self, token, email):
        with self._open_auth_token_file(mode="w") as fp:
            fp.write(jsonlib.dumps({"auth_token": token, "user_email": email}))
            aiven_credentials_filename = fp.name
        os.chmod(aiven_credentials_filename, 0o600)
        self.log.info("Aiven credentials written to: %s", aiven_credentials_filename)

    def _open_auth_token_file(self, mode="r"):
        default_token_file_path = os.path.join(envdefault.AIVEN_CONFIG_DIR, "aiven-credentials.json")
        auth_token_file_path = (os.environ.get("AIVEN_CREDENTIALS_FILE") or default_token_file_path)
        try:
            return open(auth_token_file_path, mode)
        except IOError as ex:
            if ex.errno == errno.ENOENT and mode == "w":
                aiven_dir = os.path.dirname(auth_token_file_path)
                os.makedirs(aiven_dir)
                os.chmod(aiven_dir, 0o700)
                return open(auth_token_file_path, mode)
            raise

    def _get_auth_token(self):
        token = self.args.auth_token
        if token:
            return token

        try:
            with self._open_auth_token_file() as fp:
                return jsonlib.load(fp)["auth_token"]
        except IOError as ex:
            if ex.errno == errno.ENOENT:
                return None
            raise

    def pre_run(self, func):
        self.client = client.AivenClient(base_url=self.args.url,
                                         show_http=self.args.show_http)
        # Always set CA if we have anything set at the command line or in the env
        if self.args.auth_ca is not None:
            self.client.set_ca(self.args.auth_ca)
        if func == self.user_create:
            # "user create" doesn't use authentication (yet)
            return

        if not getattr(func, "no_auth", False):
            auth_token = self._get_auth_token()
            if auth_token:
                self.client.set_auth_token(auth_token)
            elif not getattr(func, "optional_auth", False):
                raise argx.UserError("not authenticated: please login first with 'avn user login'")

    @arg.json
    def card_list(self):
        """List credit cards"""
        layout = [["card_id", "name", "country", "exp_year", "exp_month", "last4"]]
        self.print_response(self.client.get_cards(), json=self.args.json, table_layout=layout)

    def _card_get_stripe_token(self,
                               stripe_publishable_key,
                               name,
                               number,
                               exp_month,
                               exp_year,
                               cvc):
        data = {
            "card[name]": name,
            "card[number]": number,
            "card[exp_month]": exp_month,
            "card[exp_year]": exp_year,
            "card[cvc]": cvc,
            "key": stripe_publishable_key,
        }
        response = requests.post("https://api.stripe.com/v1/tokens", data=data)
        return response.json()["id"]

    @arg.json
    @arg("--cvc", help="Credit card security code", type=int, required=True)
    @arg("--exp-month", help="Card expiration month (1-12)", type=int, required=True)
    @arg("--exp-year", help="Card expiration year", type=int, required=True)
    @arg("--name", help="Name on card", required=True)
    @arg("--number", help="Credit card number", type=int, required=True)
    @arg("--update-project", help="Assign card to project")
    def card_add(self):
        """Add a credit card"""
        stripe_key = self.client.get_stripe_key()["stripe_key"]
        stripe_token = self._card_get_stripe_token(
            stripe_key,
            self.args.name,
            self.args.number,
            self.args.exp_month,
            self.args.exp_year,
            self.args.cvc,
        )
        card = self.client.add_card(stripe_token)
        if self.args.json:
            self.print_response(card, json=True)

        if self.args.update_project:
            self.client.update_project(
                project=self.args.update_project,
                card_id=card["card_id"],
            )

    @arg.json
    @arg("card-id", help="Card ID")
    @arg("--exp-month", help="Card expiration month (1-12)", type=int)
    @arg("--exp-year", help="Card expiration year", type=int)
    @arg("--name", help="Name on card")
    def card_update(self):
        """Update credit card information"""
        card = self.client.update_card(
            card_id=self.args.card_id,
            exp_month=self.args.exp_month,
            exp_year=self.args.exp_year,
            name=self.args.name,
        )
        if self.args.json:
            self.print_response(card, json=True)

    @arg.json
    @arg("card-id", help="Card ID")
    def card_remove(self):
        """Remove a credit card"""
        result = self.client.remove_card(card_id=self.args.card_id)
        if self.args.json:
            self.print_response(result, json=True)

    @arg.json
    @arg.project
    def credits_list(self):
        """List claimed credits"""
        project_name = self.get_project()
        project_credits = self.client.list_project_credits(project=project_name)
        layout = [["code", "remaining_value"]]
        self.print_response(project_credits, json=self.args.json, table_layout=layout)

    @arg.json
    @arg.project
    @arg("code", help="Credit code")
    def credits_claim(self):
        """Claim a credit code"""
        project_name = self.get_project()
        result = self.client.claim_project_credit(project=project_name, credit_code=self.args.code)
        if self.args.json:
            self.print_response(result, json=True)


if __name__ == "__main__":
    AivenCLI().main()
