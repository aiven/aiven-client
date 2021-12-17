# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from .common import UNDEFINED
from .session import get_requests_session
from urllib.parse import quote

import json
import logging
import re
import requests
import time
import warnings

try:
    from .version import __version__  # pylint: disable=no-name-in-module
except ImportError:
    __version__ = "UNKNOWN"

UNCHANGED = object()  # used as a sentinel value


class Error(Exception):
    """Request error"""

    def __init__(self, response, status=520):
        Exception.__init__(self, response.text)
        self.response = response
        self.status = status


class AivenClientBase:  # pylint: disable=old-style-class
    """Aiven Client with low-level HTTP operations"""

    def __init__(self, base_url, show_http=False, request_timeout=None):
        self.log = logging.getLogger("AivenClient")
        self.auth_token = None
        self.base_url = base_url
        self.log.debug("using %r", self.base_url)
        self.session = get_requests_session(timeout=request_timeout)
        self.http_log = logging.getLogger("aiven_http")
        self.init_http_logging(show_http)
        self.api_prefix = "/v1"

    def init_http_logging(self, show_http):
        http_handler = logging.StreamHandler()
        http_handler.setFormatter(logging.Formatter("%(message)s"))
        self.http_log.addHandler(http_handler)
        self.http_log.propagate = False
        if show_http:
            self.http_log.setLevel(logging.DEBUG)

    def set_auth_token(self, token):
        self.auth_token = token

    def set_ca(self, ca):
        self.session.verify = ca

    def _execute(self, func, method, path, body, params=None):
        url = self.base_url + path
        headers = {}
        if isinstance(body, dict):
            headers["content-type"] = "application/json"
            data = json.dumps(body)
            log_data = json.dumps(body, sort_keys=True, indent=4)
        else:
            headers["content-type"] = "application/octet-stream"
            data = body
            log_data = data or ""

        if self.auth_token:
            headers["authorization"] = "aivenv1 {token}".format(token=self.auth_token)

        self.http_log.debug("-----Request Begin-----")
        self.http_log.debug("%s %s %s", method, url, params if params else "")
        for header, header_value in headers.items():
            self.http_log.debug("%s: %s", header, header_value)

        self.http_log.debug("")
        self.http_log.debug("%s", log_data)
        self.http_log.debug("-----Request End-----")

        response = func(url, headers=headers, params=params, data=data)

        self.http_log.debug("-----Response Begin-----")
        self.http_log.debug("%s %s", response.status_code, response.reason)
        for header, header_value in response.headers.items():
            self.http_log.debug("%s: %s", header, header_value)

        self.http_log.debug("")
        if response.headers.get("content-type") == "application/json":
            self.http_log.debug("%s", json.dumps(response.json(), sort_keys=True, indent=4))
        else:
            self.http_log.debug("%s", response.text)

        self.http_log.debug("-----Response End-----")

        if not str(response.status_code).startswith("2"):
            raise Error(response, status=response.status_code)

        return response

    def get(self, path="", params=None):
        """HTTP GET"""
        return self._execute(self.session.get, "GET", path, body=None, params=params)

    def patch(self, path="", body=None, params=None):
        """HTTP PATCH"""
        return self._execute(self.session.patch, "PATCH", path, body, params)

    def post(self, path="", body=None, params=None):
        """HTTP POST"""
        return self._execute(self.session.post, "POST", path, body, params)

    def put(self, path="", body=None, params=None):
        """HTTP PUT"""
        return self._execute(self.session.put, "PUT", path, body, params)

    def delete(self, path="", body=None, params=None):
        """HTTP DELETE"""
        return self._execute(self.session.delete, "DELETE", path, body, params)

    def verify(self, op, path, body=None, params=None, result_key=None, retry=None):
        # Retry GET operations by default
        if retry is None and op == self.get:  # pylint: disable=comparison-with-callable
            attempts = 3
        else:
            attempts = 1 + (retry or 0)

        path = self.api_prefix + path

        while attempts:
            attempts -= 1
            try:
                if body is not None:
                    response = op(path=path, body=body, params=params)
                else:
                    response = op(path=path, params=params)
                break
            except requests.exceptions.ConnectionError as ex:
                if attempts <= 0:
                    raise
                self.log.warning(
                    "%s %s failed: %s: %s; retrying in 0.2 seconds, %s attempts left",
                    op.__name__.upper(),
                    path,
                    ex.__class__.__name__,
                    ex,
                    attempts,
                )
                time.sleep(0.2)

        result = response.json()
        if result.get("error"):
            raise Error(
                "server returned error: {op} {base_url}{path} {result}".format(
                    op=op.__doc__, base_url=self.base_url, path=path, result=result
                )
            )

        if result_key is not None:
            return result[result_key]
        return result

    @staticmethod
    def build_path(*parts):
        return "/" + "/".join(quote(part, safe="") for part in parts)


class AivenClient(AivenClientBase):
    """Aiven Client with high-level operations"""

    def get_service_versions(self):
        return self.verify(self.get, "/service_versions", result_key="service_versions")

    def get_service_indexes(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "index"),
            result_key="indexes",
        )

    def delete_service_index(self, project, service, index_name):
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "index", index_name),
        )

    def get_clouds(self, project):
        if project is None:
            path = "/clouds"
        else:
            path = self.build_path("project", project, "clouds")
        return self.verify(self.get, path, result_key="clouds")

    def get_service(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service),
            result_key="service",
        )

    def get_service_metrics(self, project, service, period):
        path = self.build_path("project", project, "service", service, "metrics")
        return self.verify(self.post, path, result_key="metrics", body={"period": period})

    def authenticate_user(self, email, password, otp=None, tenant_id=None):
        body = {
            "email": email,
            "password": password,
        }
        if otp is not None:
            body["otp"] = otp
        if tenant_id is not None:
            body["tenant"] = tenant_id

        return self.verify(self.post, "/userauth", body=body)

    def create_service_connection_pool(
        self,
        project,
        service,
        pool_name,
        dbname,
        username=None,
        pool_size=None,
        pool_mode=None,
    ):
        body = {"database": dbname, "pool_name": pool_name}
        if username:
            body["username"] = username
        if pool_size:
            body["pool_size"] = pool_size
        if pool_mode:
            body["pool_mode"] = pool_mode
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "connection_pool"),
            body=body,
        )

    def update_service_connection_pool(
        self,
        project,
        service,
        pool_name,
        dbname=None,
        username=UNCHANGED,
        pool_size=None,
        pool_mode=None,
    ):
        body = {}
        if username is not UNCHANGED:
            body["username"] = username
        if dbname is not None:
            body["database"] = dbname
        if pool_size is not None:
            body["pool_size"] = pool_size
        if pool_mode is not None:
            body["pool_mode"] = pool_mode
        path = self.build_path("project", project, "service", service, "connection_pool", pool_name)
        return self.verify(self.put, path, body=body)

    def delete_service_connection_pool(self, project, service, pool_name):
        path = self.build_path("project", project, "service", service, "connection_pool", pool_name)
        return self.verify(self.delete, path)

    def create_service_database(self, project, service, dbname):
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "db"),
            body={"database": dbname},
        )

    def delete_service_database(self, project, service, dbname):
        path = self.build_path("project", project, "service", service, "db", dbname)
        return self.verify(self.delete, path)

    def create_service_user(self, project, service, username, extra_params=None):
        body = {"username": username}
        if extra_params:
            body.update(extra_params)
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "user"),
            body=body,
            result_key="user",
        )

    def delete_service_user(self, project, service, username):
        path = self.build_path("project", project, "service", service, "user", username)
        return self.verify(self.delete, path)

    def get_service_user(self, project, service, username):
        path = self.build_path("project", project, "service", service, "user", username)
        return self.verify(self.get, path, result_key="user")

    def acknowledge_service_user_certificate(self, project, service, username):
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "acknowledge-renewal"}
        return self.verify(self.put, path, body=body)

    def reset_service_user_password(self, project, service, username, password):
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "reset-credentials"}
        if password is not None:
            body["new_password"] = password
        return self.verify(self.put, path, body=body)

    def set_service_user_access_control(self, project, service, username, access_control):
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "set-access-control", "access_control": access_control}
        return self.verify(self.put, path, body=body)

    def get_service_integration_endpoints(self, project):
        path = self.build_path("project", project, "integration_endpoint")
        return self.verify(self.get, path, result_key="service_integration_endpoints")

    def get_service_integration_endpoint_types(self, project):
        path = self.build_path("project", project, "integration_endpoint_types")
        return self.verify(self.get, path, result_key="endpoint_types")

    def create_service_integration_endpoint(self, project, endpoint_name, endpoint_type, user_config):
        return self.verify(
            self.post,
            self.build_path("project", project, "integration_endpoint"),
            body={
                "endpoint_name": endpoint_name,
                "endpoint_type": endpoint_type,
                "user_config": user_config,
            },
        )

    def update_service_integration_endpoint(self, project, endpoint_id, user_config):
        return self.verify(
            self.put,
            self.build_path("project", project, "integration_endpoint", endpoint_id),
            body={
                "user_config": user_config,
            },
        )

    def delete_service_integration_endpoint(self, project, endpoint_id):
        return self.verify(
            self.delete,
            self.build_path("project", project, "integration_endpoint", endpoint_id),
        )

    def get_service_integrations(self, project, service):
        path = self.build_path("project", project, "service", service, "integration")
        return self.verify(self.get, path, result_key="service_integrations")

    def get_service_integration_types(self, project):
        path = self.build_path("project", project, "integration_types")
        return self.verify(self.get, path, result_key="integration_types")

    def create_service_integration(
        self,
        project,
        integration_type,
        source_service=None,
        dest_service=None,
        source_endpoint_id=None,
        dest_endpoint_id=None,
        user_config=None,
    ):
        user_config = user_config or {}
        return self.verify(
            self.post,
            self.build_path("project", project, "integration"),
            body={
                "source_endpoint_id": source_endpoint_id,
                "source_service": source_service,
                "dest_endpoint_id": dest_endpoint_id,
                "dest_service": dest_service,
                "integration_type": integration_type,
                "user_config": user_config,
            },
        )

    def update_service_integration(self, project, integration_id, user_config):
        return self.verify(
            self.put,
            self.build_path("project", project, "integration", integration_id),
            body={
                "user_config": user_config,
            },
            result_key="service_integration",
        )

    def get_service_integration(self, project, integration_id):
        path = self.build_path("project", project, "integration", integration_id)
        return self.verify(self.get, path, result_key="service_integration")

    def delete_service_integration(self, project, integration_id):
        return self.verify(
            self.delete,
            self.build_path("project", project, "integration", integration_id),
        )

    def create_service_task(self, project, service, body):
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "task"),
            body=body,
        )

    def get_service_task(self, project, service, task_id):
        path = self.build_path("project", project, "service", service, "task", task_id)
        return self.verify(self.get, path, result_key="task")

    def get_service_topic(self, project, service, topic):
        path = self.build_path("project", project, "service", service, "topic", topic)
        return self.verify(self.get, path, result_key="topic")

    def _set_namespace_options(
        self,
        ns,
        ns_ret=None,
        ns_res=None,
        ns_blocksize_dur=None,
        ns_block_data_expiry_dur=None,
        ns_buffer_future_dur=None,
        ns_buffer_past_dur=None,
        ns_writes_to_commitlog=None
    ):
        re_ns_duration = re.compile(r'\d+[smhd]')

        def _validate_ns_dur(val):
            if not re_ns_duration.match(val):
                raise ValueError(f"Invalid namespace duration value '{val}'")

        ns["options"] = ns.get("options", {})
        ns["options"]["retention_options"] = ns["options"].get("retention_options", {})
        if ns_ret:
            _validate_ns_dur(ns_ret)
            ns["options"]["retention_options"]["retention_period_duration"] = ns_ret
        if ns_res:
            _validate_ns_dur(ns_res)
            ns["resolution"] = ns_res
        if ns_blocksize_dur:
            _validate_ns_dur(ns_blocksize_dur)
            ns["options"]["retention_options"]["blocksize_duration"] = ns_blocksize_dur
        if ns_block_data_expiry_dur:
            _validate_ns_dur(ns_block_data_expiry_dur)
            ns["options"]["retention_options"]["block_data_expiry_duration"] = ns_block_data_expiry_dur
        if ns_buffer_future_dur:
            _validate_ns_dur(ns_buffer_future_dur)
            ns["options"]["retention_options"]["buffer_future_duration"] = ns_buffer_future_dur
        if ns_buffer_past_dur:
            _validate_ns_dur(ns_buffer_past_dur)
            ns["options"]["retention_options"]["buffer_past_duration"] = ns_buffer_past_dur
        if ns_writes_to_commitlog is not None:
            ns["options"]["writes_to_commitlog"] = bool(ns_writes_to_commitlog)

    def list_m3_namespaces(self, project, service):
        service_res = self.get_service(project=project, service=service)
        return service_res.get("user_config", {}).get("namespaces", [])

    def delete_m3_namespace(self, project, service, ns_name):
        service_res = self.get_service(project=project, service=service)
        old_namespaces = service_res.get("user_config", {}).get("namespaces", [])
        new_namespaces = [ns for ns in old_namespaces if ns["name"] != ns_name]
        if len(old_namespaces) == len(new_namespaces):
            raise KeyError(f"Namespace '{ns_name}' does not exist")
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {
                "namespaces": new_namespaces
            }},
        )

    def add_m3_namespace(
        self,
        project,
        service,
        ns_name,
        ns_type,
        ns_ret,
        ns_res=None,
        ns_blocksize_dur=None,
        ns_block_data_expiry_dur=None,
        ns_buffer_future_dur=None,
        ns_buffer_past_dur=None,
        ns_writes_to_commitlog=None
    ):
        service_res = self.get_service(project=project, service=service)
        namespaces = service_res.get("user_config", {}).get("namespaces", [])
        valid_namespace_types = {'unaggregated', 'aggregated'}
        if ns_type not in valid_namespace_types:
            raise ValueError(f"Invalid namespace type {ns_type}, valid types {valid_namespace_types}")
        new_namespace = {
            "name": ns_name,
            "type": ns_type,
        }
        self._set_namespace_options(
            ns=new_namespace,
            ns_ret=ns_ret,
            ns_res=ns_res,
            ns_blocksize_dur=ns_blocksize_dur,
            ns_block_data_expiry_dur=ns_block_data_expiry_dur,
            ns_buffer_future_dur=ns_buffer_future_dur,
            ns_buffer_past_dur=ns_buffer_past_dur,
            ns_writes_to_commitlog=ns_writes_to_commitlog
        )
        namespaces.append(new_namespace)
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {
                "namespaces": namespaces
            }},
        )

    def update_m3_namespace(
        self,
        project,
        service,
        ns_name,
        ns_ret=None,
        ns_res=None,
        ns_blocksize_dur=None,
        ns_block_data_expiry_dur=None,
        ns_buffer_future_dur=None,
        ns_buffer_past_dur=None,
        ns_writes_to_commitlog=None
    ):
        service_res = self.get_service(project=project, service=service)
        namespaces = service_res.get("user_config", {}).get("namespaces", [])
        namespace = None
        for ns in namespaces:
            if ns["name"] == ns_name:
                namespace = ns
        if not namespace:
            raise KeyError(f"Namespace '{ns_name}' does not exist")
        self._set_namespace_options(
            ns=namespace,
            ns_ret=ns_ret,
            ns_res=ns_res,
            ns_blocksize_dur=ns_blocksize_dur,
            ns_block_data_expiry_dur=ns_block_data_expiry_dur,
            ns_buffer_future_dur=ns_buffer_future_dur,
            ns_buffer_past_dur=ns_buffer_past_dur,
            ns_writes_to_commitlog=ns_writes_to_commitlog
        )
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {
                "namespaces": namespaces
            }},
        )

    def list_service_topics(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "topic"),
            result_key="topics",
        )

    def create_service_topic(
        self,
        project,
        service,
        topic,
        partitions,
        replication,
        min_insync_replicas,
        retention_bytes,
        retention_hours,
        cleanup_policy,
        tags=None,
    ):
        body = {
            "cleanup_policy": cleanup_policy,
            "min_insync_replicas": min_insync_replicas,
            "topic_name": topic,
            "partitions": partitions,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        }
        if tags is not None:
            body.update({"tags": tags})
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "topic"),
            body=body,
        )

    def update_service_topic(
        self,
        project,
        service,
        topic,
        partitions,
        retention_bytes,
        retention_hours,
        min_insync_replicas,
        replication=None,
        tags=None,
    ):
        body = {
            "partitions": partitions,
            "min_insync_replicas": min_insync_replicas,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        }
        if tags is not None:
            body.update({"tags": tags})
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service, "topic", topic),
            body=body,
        )

    def delete_service_topic(self, project, service, topic):
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "topic", topic),
        )

    def list_service_elasticsearch_acl_config(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "elasticsearch", "acl"),
        )

    @staticmethod
    def _add_es_acl_rules(config, user, rules):
        user_acl = None
        for acl in config["acls"]:
            if acl["username"] == user:
                user_acl = acl
                break
        if user_acl is None:  # new user
            user_acl = {"username": user, "rules": []}
            config["acls"].append(user_acl)
        patterns = {rule["index"]: rule["permission"] for rule in user_acl["rules"]}
        patterns.update(rules)
        user_acl["rules"] = [{"index": index, "permission": permission} for index, permission in patterns.items()]

    @staticmethod
    def _del_es_acl_rules(config, user, rules):
        acls = []
        user_acl = None
        for acl in config["acls"]:
            if acl["username"] != user:
                acls.append(acl)
            if acl["username"] == user:
                user_acl = acl
        config["acls"] = acls
        if user_acl is None:  # No rules existed for the user
            return
        if not rules:  # removing all rules
            return

        # Remove the requested rules
        user_acl["rules"] = [rule for rule in user_acl["rules"] if rule["index"] not in rules]
        config["acls"].append(user_acl)

    def update_service_elasticsearch_acl_config(
        self,
        project,
        service,
        enabled=None,
        extended_acl=None,
        username=None,
        add_rules=None,
        del_rules=None,
    ):
        acl_config = self.list_service_elasticsearch_acl_config(project, service)["elasticsearch_acl_config"]
        if enabled is not None:
            acl_config["enabled"] = enabled
        if extended_acl is not None:
            acl_config["extendedAcl"] = extended_acl
        if add_rules is not None:
            try:
                rules = {index.strip(): permission.strip() for index, permission in [rule.split("/") for rule in add_rules]}
            except ValueError as ex:
                raise ValueError("Unrecognized index-pattern/permission rule") from ex
            self._add_es_acl_rules(config=acl_config, user=username, rules=rules)
        if del_rules is not None:
            self._del_es_acl_rules(
                config=acl_config,
                user=username,
                rules=set(rule.strip() for rule in del_rules),
            )

        path = self.build_path("project", project, "service", service, "elasticsearch", "acl")
        return self.verify(self.put, path, body={"elasticsearch_acl_config": acl_config})

    def add_service_kafka_acl(self, project, service, permission, topic, username):
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "acl"),
            body={
                "permission": permission,
                "topic": topic,
                "username": username,
            },
        )

    def create_connector_config_based_on_current(self, project, service, connector_name, config_update):
        current_connectors = self.list_kafka_connectors(project, service)
        connector = [conn for conn in current_connectors["connectors"] if conn["name"] == connector_name]
        if not connector:
            raise KeyError("Current configuration for connector '{}' not in connector list".format(connector_name))
        assert len(connector) == 1
        full_config = connector[0]["config"]
        full_config.update(config_update)
        return full_config

    def delete_service_kafka_acl(self, project, service, acl_id):
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "acl", acl_id),
        )

    def get_available_kafka_connectors(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "available-connectors"),
        )

    def list_kafka_connectors(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "connectors"),
        )

    def get_kafka_connector_status(self, project, service, connector_name):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connectors",
            connector_name,
            "status",
        )
        return self.verify(self.get, path)

    def get_kafka_connector_schema(self, project, service, connector_name):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connector-plugins",
            connector_name,
            "configuration",
        )
        return self.verify(self.get, path)

    def create_kafka_connector(self, project, service, config):
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "connectors"),
            body=config,
        )

    def update_kafka_connector(self, project, service, connector_name, config, fetch_current=False):
        path = self.build_path("project", project, "service", service, "connectors", connector_name)
        if fetch_current:
            config = self.create_connector_config_based_on_current(project, service, connector_name, config)
        return self.verify(self.put, path, body=config)

    def delete_kafka_connector(self, project, service, connector_name):
        path = self.build_path("project", project, "service", service, "connectors", connector_name)
        return self.verify(self.delete, path)

    def pause_kafka_connector(self, project, service, connector_name):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connectors",
            connector_name,
            "pause",
        )
        return self.verify(self.post, path)

    def resume_kafka_connector(self, project, service, connector_name):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connectors",
            connector_name,
            "resume",
        )
        return self.verify(self.post, path)

    def restart_kafka_connector(self, project, service, connector_name):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connectors",
            connector_name,
            "restart",
        )
        return self.verify(self.post, path)

    def restart_kafka_connector_task(self, project, service, connector_name, task_id):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "connectors",
            connector_name,
            "tasks",
            task_id,
            "restart",
        )
        return self.verify(self.post, path)

    def get_schema(self, project, service, schema_id):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "schemas",
            "ids",
            schema_id,
        )
        return self.verify(self.get, path)

    def check_schema_compatibility(self, project, service, subject, version, schema):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "compatibility",
            "subjects",
            subject,
            "versions",
            version,
        )
        return self.verify(self.post, path, body={"schema": schema})

    def get_schema_global_configuration(self, project, service):
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config")
        return self.verify(self.get, path)

    def update_schema_global_configuration(self, project, service, compatibility):
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config")
        return self.verify(self.put, path, body={"compatibility": compatibility})

    def get_schema_subject_configuration(self, project, service, subject):
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config", subject)
        return self.verify(self.get, path)

    def update_schema_subject_configuration(self, project, service, subject, compatibility):
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config", subject)
        return self.verify(self.put, path, body={"compatibility": compatibility})

    def list_schema_subjects(self, project, service):
        path = self.build_path("project", project, "service", service, "kafka", "schema", "subjects")
        return self.verify(self.get, path)

    def delete_schema_subject(self, project, service, subject):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
        )
        return self.verify(self.delete, path)

    def get_schema_subject_version(self, project, service, subject, version):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
            "versions",
            version,
        )
        return self.verify(self.get, path)

    def get_schema_subject_version_schema(self, project, service, subject, version):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
            "versions",
            version,
            "schema",
        )
        return self.verify(self.get, path)

    def list_schema_subject_versions(self, project, service, subject):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
            "versions",
        )
        return self.verify(self.get, path)

    def create_schema_subject_version(self, project, service, subject, schema):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
            "versions",
        )
        return self.verify(self.post, path, body={"schema": schema})

    def delete_schema_subject_version(self, project, service, subject, version):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "kafka",
            "schema",
            "subjects",
            subject,
            "versions",
            version,
        )
        return self.verify(self.delete, path)

    def list_mirrormaker_replication_flows(self, project, service):
        path = self.build_path("project", project, "service", service, "mirrormaker", "replication-flows")
        return self.verify(self.get, path, result_key="replication_flows")

    def create_mirrormaker_replication_flow(self, project, service, source_cluster, target_cluster, config):
        path = self.build_path("project", project, "service", service, "mirrormaker", "replication-flows")
        body = {}
        body.update(config)
        body["source_cluster"] = source_cluster
        body["target_cluster"] = target_cluster
        return self.verify(self.post, path, body=body)

    def update_mirrormaker_replication_flow(self, project, service, source_cluster, target_cluster, config):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "mirrormaker",
            "replication-flows",
            source_cluster,
            target_cluster,
        )
        body = {}
        body.update(config)
        return self.verify(self.put, path, body=body, result_key="replication_flow")

    def get_mirrormaker_replication_flow(self, project, service, source_cluster, target_cluster):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "mirrormaker",
            "replication-flows",
            source_cluster,
            target_cluster,
        )
        return self.verify(self.get, path, result_key="replication_flow")

    def delete_mirrormaker_replication_flow(self, project, service, source_cluster, target_cluster):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "mirrormaker",
            "replication-flows",
            source_cluster,
            target_cluster,
        )
        return self.verify(self.delete, path)

    def list_flink_tables(self, project, service):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "flink",
            "table",
        )
        return self.verify(
            self.get,
            path,
            result_key="tables",
        )

    def create_flink_table(
        self,
        project,
        service,
        integration_id,
        table_name,
        schema_sql,
        kafka_topic=None,
        kafka_connector_type=None,
        kafka_key_format=None,
        kafka_key_fields=None,
        kafka_value_format=None,
        kafka_startup_mode=None,
        jdbc_table=None,
        like_options=None
    ):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "flink",
            "table",
        )
        body = {
            "integration_id": integration_id,
            "name": table_name,
            "schema_sql": schema_sql,
        }
        if kafka_topic:
            body["kafka_topic"] = kafka_topic
        if kafka_connector_type:
            body["kafka_connector_type"] = kafka_connector_type
        if kafka_key_format:
            body["kafka_key_format"] = kafka_key_format
        if kafka_key_fields:
            body["kafka_key_fields"] = kafka_key_fields
        if kafka_value_format:
            body["kafka_value_format"] = kafka_value_format
        if kafka_startup_mode:
            body["kafka_startup_mode"] = kafka_startup_mode
        if jdbc_table:
            body["jdbc_table"] = jdbc_table
        if like_options:
            body["like_options"] = like_options
        return self.verify(self.post, path, body=body)

    def get_flink_table(self, project, service, table_id):
        path = self.build_path("project", project, "service", service, "flink", "table", table_id)
        return self.verify(
            self.get,
            path,
        )

    def delete_flink_table(self, project, service, table_id):
        path = self.build_path("project", project, "service", service, "flink", "table", table_id)
        return self.verify(self.delete, path)

    def create_flink_job(
        self,
        project,
        service,
        statement,
        job_name,
        table_ids=None,
    ):
        if table_ids is None:
            table_ids = []
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "flink",
            "job",
        )
        body = {
            "statement": statement,
            "table_ids": table_ids,
            "job_name": job_name,
        }
        return self.verify(self.post, path, body=body)

    def list_flink_jobs(self, project, service):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "flink",
            "job",
        )

        return self.verify(
            self.get,
            path,
            result_key="jobs",
        )

    def get_flink_job(self, project, service, job_id):
        path = self.build_path("project", project, "service", service, "flink", "job", job_id)
        return self.verify(
            self.get,
            path,
        )

    def cancel_flink_job(self, project, service, job_id):
        path = self.build_path("project", project, "service", service, "flink", "job", job_id, "cancel")
        return self.verify(
            self.post,
            path,
        )

    def list_project_vpcs(self, project):
        return self.verify(self.get, self.build_path("project", project, "vpcs"))

    def create_project_vpc(self, project, cloud, network_cidr, peering_connections):
        return self.verify(
            self.post,
            self.build_path("project", project, "vpcs"),
            body={
                "cloud_name": cloud,
                "network_cidr": network_cidr,
                "peering_connections": peering_connections,
            },
        )

    def request_project_vpc(self, project, cloud, network_cidr, peering_connections):
        warnings.warn("Use the create_project_vpc method", DeprecationWarning)
        return self.create_project_vpc(
            project=project,
            cloud=cloud,
            network_cidr=network_cidr,
            peering_connections=peering_connections,
        )

    def get_project_vpc(self, project, project_vpc_id):
        return self.verify(self.get, self.build_path("project", project, "vpcs", project_vpc_id))

    def delete_project_vpc(self, project, project_vpc_id):
        return self.verify(self.delete, self.build_path("project", project, "vpcs", project_vpc_id))

    def create_project_vpc_peering_connection(
        self,
        project,
        project_vpc_id,
        peer_cloud_account,
        peer_vpc,
        peer_region=None,
        peer_resource_group=None,
        peer_azure_app_id=None,
        peer_azure_tenant_id=None,
        user_peer_network_cidrs=None,
    ):
        path = self.build_path("project", project, "vpcs", project_vpc_id, "peering-connections")
        body = {
            "peer_cloud_account": peer_cloud_account,
            "peer_vpc": peer_vpc,
        }
        if peer_region is not None:
            body["peer_region"] = peer_region
        if peer_resource_group is not None:
            body["peer_resource_group"] = peer_resource_group
        if peer_azure_app_id is not None:
            body["peer_azure_app_id"] = peer_azure_app_id
        if peer_azure_tenant_id is not None:
            body["peer_azure_tenant_id"] = peer_azure_tenant_id
        if user_peer_network_cidrs is not None:
            body["user_peer_network_cidrs"] = user_peer_network_cidrs
        return self.verify(self.post, path, body=body)

    def request_project_vpc_peering_connection(self, project, project_vpc_id, peer_cloud_account, peer_vpc):
        warnings.warn("Use the create_project_vpc_peering_connection method", DeprecationWarning)
        return self.create_project_vpc_peering_connection(
            project=project,
            project_vpc_id=project_vpc_id,
            peer_cloud_account=peer_cloud_account,
            peer_vpc=peer_vpc,
        )

    def delete_project_vpc_peering_connection(
        self,
        project,
        project_vpc_id,
        peer_cloud_account,
        peer_vpc,
        peer_region=None,
        peer_resource_group=UNDEFINED,
    ):
        path = self.build_path(
            "project",
            project,
            "vpcs",
            project_vpc_id,
            "peering-connections",
            "peer-accounts",
            peer_cloud_account,
        )
        if peer_resource_group is not UNDEFINED and peer_resource_group is not None:
            path += self.build_path("peer-resource-groups", peer_resource_group)
        path += self.build_path("peer-vpcs", peer_vpc)
        if peer_region is not None:
            path += self.build_path("peer-regions", peer_region)
        return self.verify(self.delete, path)

    def get_project_vpc_peering_connection(
        self,
        project,
        project_vpc_id,
        peer_cloud_account,
        peer_vpc,
        peer_region=UNDEFINED,
        peer_resource_group=UNDEFINED,
    ):
        vpc = self.get_project_vpc(project=project, project_vpc_id=project_vpc_id)
        for peering_connection in vpc["peering_connections"]:
            # pylint: disable=too-many-boolean-expressions
            if (
                peering_connection["peer_cloud_account"] == peer_cloud_account and peering_connection["peer_vpc"] == peer_vpc
                and (peer_region is UNDEFINED or peering_connection["peer_region"] == peer_region)
                and (peer_resource_group is UNDEFINED or peering_connection["peer_resource_group"] == peer_resource_group)
            ):
                return peering_connection
        if peer_resource_group is not UNDEFINED and peer_resource_group is not None:
            peer_resource_group_msg = " in resource group {}".format(peer_resource_group)
        else:
            peer_resource_group_msg = ""
        if peer_region is not UNDEFINED and peer_region is not None:
            peer_region_msg = " in region {}".format(peer_region)
        else:
            peer_region_msg = ""
        msg = "Peering connection to peer account {}{} VPC {}{} does not exist".format(
            peer_cloud_account,
            peer_resource_group_msg,
            peer_vpc,
            peer_region_msg,
        )
        raise KeyError(msg)

    def update_project_vpc_user_peer_network_cidrs(self, project, project_vpc_id, add=None, delete=None):
        path = self.build_path(
            "project",
            project,
            "vpcs",
            project_vpc_id,
            "user-peer-network-cidrs",
        )
        body = {}
        if add:
            body["add"] = add
        if delete:
            body["delete"] = delete
        return self.verify(self.put, path, body=body)

    def list_project_tags(self, project):
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        return self.verify(self.get, path)

    def update_project_tags(self, project, tag_updates):
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        body = {"tags": tag_updates}
        return self.verify(self.patch, path, body=body)

    def replace_project_tags(self, project, tags):
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        body = {"tags": tags}
        return self.verify(self.put, path, body=body)

    def create_service(
        self,
        project,
        service,
        service_type,
        plan,
        disk_space_mb=None,
        cloud=None,
        user_config=None,
        project_vpc_id=UNDEFINED,
        service_integrations=None,
        termination_protection=False,
        static_ips=(),
    ):
        user_config = user_config or {}
        body = {
            "cloud": cloud,
            "plan": plan,
            "service_integrations": service_integrations,
            "service_name": service,
            "service_type": service_type,
            "user_config": user_config,
            "termination_protection": termination_protection,
            "static_ips": static_ips,
        }
        if disk_space_mb is not None:
            body["disk_space_mb"] = disk_space_mb
        if project_vpc_id is not UNDEFINED:
            body["project_vpc_id"] = project_vpc_id
        return self.verify(
            self.post,
            self.build_path("project", project, "service"),
            body=body,
            result_key="service",
        )

    def update_service(
        self,
        project,
        service,
        cloud=None,
        maintenance=None,
        user_config=None,
        plan=None,
        disk_space_mb=None,
        karapace=None,
        powered=None,
        termination_protection=None,
        project_vpc_id=UNDEFINED,
    ):
        user_config = user_config or {}
        body = {}
        if cloud is not None:
            body["cloud"] = cloud
        if maintenance is not None:
            body["maintenance"] = maintenance
        if plan is not None:
            body["plan"] = plan
        if disk_space_mb is not None:
            body["disk_space_mb"] = disk_space_mb
        if powered is not None:
            body["powered"] = powered
        if karapace is not None:
            body["karapace"] = karapace
        if user_config is not None:
            body["user_config"] = user_config
        if project_vpc_id is not UNDEFINED:
            body["project_vpc_id"] = project_vpc_id
        if termination_protection is not None:
            body["termination_protection"] = termination_protection

        path = self.build_path("project", project, "service", service)
        return self.verify(self.put, path, body=body, result_key="service")

    def reset_service_credentials(self, project, service):
        path = self.build_path("project", project, "service", service, "credentials", "reset")
        return self.verify(self.put, path, result_key="service")

    def _privatelink_path(self, project, service, cloud_provider, *rest):
        return self.build_path("project", project, "service", service, "privatelink", cloud_provider, *rest)

    def create_service_privatelink_aws(self, project, service, principals):
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.post, path, body={"principals": principals})

    def update_service_privatelink_aws(self, project, service, principals):
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.put, path, body={"principals": principals})

    def delete_service_privatelink_aws(self, project, service):
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.delete, path)

    def get_service_privatelink_aws(self, project, service):
        path = self._privatelink_path(project, service, "aws")
        return self.verify(self.get, path)

    def list_service_privatelink_aws_connections(self, project, service):
        path = self._privatelink_path(project, service, "aws") + "/connections"
        return self.verify(self.get, path, result_key="connections")

    def create_service_privatelink_azure(self, project, service, user_subscription_ids):
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.post, path, body={"user_subscription_ids": user_subscription_ids})

    def refresh_service_privatelink_azure(self, project, service):
        path = self._privatelink_path(project, service, "azure", "refresh")
        return self.verify(self.post, path)

    def update_service_privatelink_azure(self, project, service, user_subscription_ids):
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.put, path, body={"user_subscription_ids": user_subscription_ids})

    def update_service_privatelink_connection_azure(self, project, service, privatelink_connection_id, user_ip_address):
        path = self._privatelink_path(project, service, "azure", "connections", privatelink_connection_id)
        return self.verify(self.put, path, body={"user_ip_address": user_ip_address})

    def approve_service_privatelink_connection_azure(self, project, service, privatelink_connection_id):
        path = self._privatelink_path(project, service, "azure", "connections", privatelink_connection_id, "approve")
        return self.verify(self.post, path)

    def delete_service_privatelink_azure(self, project, service):
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.delete, path)

    def get_service_privatelink_azure(self, project, service):
        path = self._privatelink_path(project, service, "azure")
        return self.verify(self.get, path)

    def list_service_privatelink_azure_connections(self, project, service):
        path = self._privatelink_path(project, service, "azure") + "/connections"
        return self.verify(self.get, path, result_key="connections")

    def list_privatelink_cloud_availability(self, project):
        path = self.build_path("project", project, "privatelink-availability")
        return self.verify(self.get, path, result_key="privatelink_availability")

    def _static_ip_address_path(self, project, *parts):
        return self.build_path("project", project, "static-ips", *parts)

    def list_static_ip_addresses(self, project):
        path = self._static_ip_address_path(project)
        return self.verify(self.get, path, result_key="static_ips")

    def create_static_ip_address(self, project, cloud_name):
        path = self._static_ip_address_path(project)
        return self.verify(self.post, path, body={"cloud_name": cloud_name})

    def associate_static_ip_address(self, project, static_ip_id, service_name):
        path = self._static_ip_address_path(project, static_ip_id, "association")
        return self.verify(self.post, path, body={"service_name": service_name})

    def dissociate_static_ip_address(self, project, static_ip_id):
        path = self._static_ip_address_path(project, static_ip_id, "association")
        return self.verify(self.delete, path)

    def delete_static_ip_address(self, project, static_ip_id):
        path = self._static_ip_address_path(project, static_ip_id)
        return self.verify(self.delete, path)

    def delete_service(self, project, service):
        return self.verify(self.delete, self.build_path("project", project, "service", service))

    def get_pg_service_current_queries(self, project, service):
        warnings.warn("Use the get_service_current_queries method", DeprecationWarning)
        return self.get_service_current_queries(project, service)

    def get_pg_service_query_stats(self, project, service):
        warnings.warn("Use the get_service_query_stats method", DeprecationWarning)
        return self.get_service_query_stats(project, service, service_type="pg")

    def reset_pg_service_query_stats(self, project, service):
        warnings.warn("Use the reset_service_query_stats method", DeprecationWarning)
        return self.reset_service_query_stats(project, service)

    def get_service_current_queries(self, project, service):
        path = self.build_path("project", project, "service", service, "query", "activity")
        return self.verify(
            self.post,
            path,
            result_key="queries",
            body={
                "limit": 100,
                "order_by": "query_duration:desc"
            },
        )

    def get_service_query_stats(self, project, service, service_type=None):
        if service_type is None:
            service_type = self.get_service(project, service)["service_type"]
        path = self.build_path("project", project, "service", service, service_type, "query", "stats")
        return self.verify(
            self.post,
            path,
            result_key="queries",
            body={
                "limit": 100,
                "order_by": "calls:desc" if service_type == "pg" else "count_star:desc",
            },
        )

    def reset_service_query_stats(self, project, service):
        path = self.build_path("project", project, "service", service, "query", "stats", "reset")
        return self.verify(self.put, path, result_key="queries")

    def list_service_tags(self, project, service):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        return self.verify(self.get, path)

    def update_service_tags(self, project, service, tag_updates):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        body = {"tags": tag_updates}
        return self.verify(self.patch, path, body=body)

    def replace_service_tags(self, project, service, tags):
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        body = {"tags": tags}
        return self.verify(self.put, path, body=body)

    def get_services(self, project):
        return self.verify(
            self.get,
            self.build_path("project", project, "service"),
            result_key="services",
        )

    def get_service_types(self, project):
        if project is None:
            path = "/service_types"
        else:
            path = self.build_path("project", project, "service_types")
        return self.verify(self.get, path, result_key="service_types")

    def create_account(self, account_name):
        body = {
            "account_name": account_name,
        }
        return self.verify(self.post, "/account", body=body, result_key="account")

    def delete_account(self, account_id):
        return self.verify(self.delete, self.build_path("account", account_id))

    def update_account(self, account_id, account_name):
        body = {
            "account_name": account_name,
        }
        return self.verify(
            self.put,
            self.build_path("account", account_id),
            body=body,
            result_key="account",
        )

    def get_accounts(self):
        return self.verify(self.get, "/account", result_key="accounts")

    def create_account_authentication_method(self, account_id, method_name, method_type, options=None):
        body = dict(options) if options else {}
        body["authentication_method_name"] = method_name
        body["authentication_method_type"] = method_type
        path = self.build_path("account", account_id, "authentication")
        return self.verify(self.post, path, body=body, result_key="authentication_method")

    def delete_account_authentication_method(self, account_id, authentication_id):
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "authentication", authentication_id),
        )

    def update_account_authentication_method(
        self,
        account_id,
        authentication_id,
        method_name=None,
        method_enable=None,
        options=None,
    ):
        body = dict(options) if options else {}
        if method_name is not None:
            body["authentication_method_name"] = method_name
        if method_enable is not None:
            body["authentication_method_enabled"] = method_enable

        path = self.build_path("account", account_id, "authentication", authentication_id)
        return self.verify(self.put, path, body=body, result_key="authentication_method")

    def get_account_authentication_methods(self, account_id):
        path = self.build_path("account", account_id, "authentication")
        return self.verify(self.get, path, result_key="authentication_methods")

    def create_project(
        self,
        project,
        account_id=None,
        billing_group_id=None,
        card_id=None,
        cloud=None,
        copy_from_project=None,
        country_code=None,
        billing_address=None,
        billing_currency=None,
        billing_extra_text=None,
        vat_id=None,
        billing_emails=None,
        tech_emails=None,
        use_source_project_billing_group=None,
    ):
        body = {
            "card_id": card_id,
            "cloud": cloud,
            "project": project,
        }
        if account_id is not None:
            body["account_id"] = account_id
        if billing_group_id is not None:
            body["billing_group_id"] = billing_group_id
        if copy_from_project is not None:
            body["copy_from_project"] = copy_from_project
        if country_code is not None:
            body["country_code"] = country_code
        if billing_address is not None:
            body["billing_address"] = billing_address
        if billing_currency is not None:
            body["billing_currency"] = billing_currency
        if billing_extra_text is not None:
            body["billing_extra_text"] = billing_extra_text
        if vat_id is not None:
            body["vat_id"] = vat_id
        if billing_emails is not None:
            body["billing_emails"] = [{"email": email} for email in billing_emails]
        if tech_emails is not None:
            body["tech_emails"] = [{"email": email} for email in tech_emails]
        if use_source_project_billing_group is not None:
            body["use_source_project_billing_group"] = use_source_project_billing_group

        return self.verify(self.post, "/project", body=body, result_key="project")

    def delete_project(self, project):
        return self.verify(self.delete, self.build_path("project", project))

    def get_project(self, project):
        return self.verify(self.get, self.build_path("project", project), result_key="project")

    def get_projects(self):
        return self.verify(self.get, "/project", result_key="projects")

    def update_project(
        self,
        project,
        new_project_name=None,
        account_id=None,
        card_id=None,
        cloud=None,
        country_code=None,
        billing_address=None,
        billing_currency=None,
        billing_extra_text=None,
        vat_id=None,
        billing_emails=None,
        tech_emails=None,
    ):
        body = {}
        if new_project_name is not None:
            body["project_name"] = new_project_name
        if account_id is not None:
            body["account_id"] = account_id
        if card_id is not None:
            body["card_id"] = card_id
        if cloud is not None:
            body["cloud"] = cloud
        if country_code is not None:
            body["country_code"] = country_code
        if billing_address is not None:
            body["billing_address"] = billing_address
        if billing_currency is not None:
            body["billing_currency"] = billing_currency
        if billing_extra_text is not None:
            body["billing_extra_text"] = billing_extra_text
        if vat_id is not None:
            body["vat_id"] = vat_id
        if billing_emails is not None:
            body["billing_emails"] = [{"email": email} for email in billing_emails]
        if tech_emails is not None:
            body["tech_emails"] = [{"email": email} for email in tech_emails]

        return self.verify(
            self.put,
            self.build_path("project", project),
            body=body,
            result_key="project",
        )

    def get_project_ca(self, project):
        return self.verify(self.get, self.build_path("project", project, "kms", "ca"))

    def get_service_ca(self, project, service, ca):
        path = self.build_path("project", project, "service", service, "kms", "ca", ca)
        return self.verify(self.get, path)

    def get_service_keypair(self, project, service, keypair):
        path = self.build_path("project", project, "service", service, "kms", "keypairs", keypair)
        return self.verify(self.get, path)

    def invite_project_user(self, project, user_email, member_type=None):
        body = {
            "user_email": user_email,
        }
        if member_type is not None:
            body["member_type"] = member_type
        return self.verify(self.post, self.build_path("project", project, "invite"), body=body)

    def remove_project_user(self, project, user_email):
        return self.verify(self.delete, self.build_path("project", project, "user", user_email))

    def list_project_users(self, project):
        return self.verify(self.get, self.build_path("project", project, "users"), result_key="users")

    def list_invited_project_users(self, project):
        return self.verify(self.get, self.build_path("project", project, "users"), result_key="invitations")

    def create_user(self, email, password, real_name, *, tenant=None):
        request = {
            "email": email,
            "real_name": real_name,
        }
        if tenant is not None:
            request["tenant"] = tenant
        if password is not None:
            request["password"] = password
        return self.verify(self.post, "/user", body=request)

    def get_user_info(self):
        return self.verify(self.get, "/me", result_key="user")

    def access_token_create(self, description, extend_when_used=False, max_age_seconds=None):
        request = {
            "description": description,
            "extend_when_used": extend_when_used,
            "max_age_seconds": max_age_seconds,
        }
        return self.verify(self.post, "/access_token", body=request)

    def access_token_revoke(self, token_prefix):
        return self.verify(self.delete, self.build_path("access_token", token_prefix))

    def access_token_update(self, token_prefix, description):
        request = {"description": description}
        return self.verify(self.put, self.build_path("access_token", token_prefix), body=request)

    def access_tokens_list(self):
        return self.verify(self.get, "/access_token", result_key="tokens")

    def expire_user_tokens(self):
        return self.verify(self.post, "/me/expire_tokens")

    def get_service_logs(self, project, service, sort_order=None, offset=None, limit=100):
        body = {"limit": limit}
        if offset is not None:
            body["offset"] = str(offset)
        if sort_order is not None:
            body["sort_order"] = sort_order
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "logs"),
            body=body,
        )

    def get_events(self, project, limit=100):
        params = {"limit": limit}
        return self.verify(
            self.get,
            self.build_path("project", project, "events"),
            params=params,
            result_key="events",
        )

    def get_cards(self):
        return self.verify(self.get, "/card", result_key="cards")

    def add_card(self, stripe_token):
        request = {
            "stripe_token": stripe_token,
        }
        return self.verify(self.post, "/card", body=request, result_key="card")

    def update_card(self, card_id, **kwargs):
        keys = {"exp_month", "exp_year", "name"}
        wrong = set(kwargs) - keys
        assert not wrong, "invalid arguments to update_card: {!r}".format(wrong)
        request = {}
        for key in keys:
            value = kwargs.get(key)
            if value is not None:
                if key in {"exp_month", "exp_year"}:
                    expected = int
                else:
                    expected = str

                assert isinstance(value, expected), "expected '{}' type for argument '{}'".format(expected, key)

                request[key] = value

        return self.verify(self.put, self.build_path("card", card_id), body=request, result_key="card")

    def remove_card(self, card_id):
        return self.verify(self.delete, self.build_path("card", card_id))

    def get_stripe_key(self):
        return self.verify(self.get, self.build_path("config", "stripe_key"))

    def list_project_credits(self, project):
        return self.verify(
            self.get,
            self.build_path("project", project, "credits"),
            result_key="credits",
        )

    def claim_project_credit(self, project, credit_code):
        return self.verify(
            self.post,
            self.build_path("project", project, "credits"),
            body={"code": credit_code},
            result_key="credit",
        )

    def create_billing_group(
        self,
        billing_group_name,
        *,
        account_id=None,
        card_id=None,
        vat_id=None,
        billing_currency=None,
        billing_extra_text=None,
        billing_emails=None,
        company=None,
        address_lines=None,
        country_code=None,
        city=None,
        state=None,
        zip_code=None,
    ):
        body = {"billing_group_name": billing_group_name}
        if account_id is not None:
            body["account_id"] = account_id
        if card_id is not None:
            body["card_id"] = card_id
        if vat_id is not None:
            body["vat_id"] = vat_id
        if billing_currency is not None:
            body["billing_currency"] = billing_currency
        if billing_extra_text is not None:
            body["billing_extra_text"] = billing_extra_text
        if billing_emails is not None:
            body["billing_emails"] = [{"email": email} for email in billing_emails]
        if company is not None:
            body["company"] = company
        if address_lines is not None:
            body["address_lines"] = address_lines
        if country_code is not None:
            body["country_code"] = country_code
        if city is not None:
            body["city"] = city
        if state is not None:
            body["state"] = state
        if zip_code is not None:
            body["zip_code"] = zip_code

        return self.verify(self.post, "/billing-group", body=body, result_key="billing_group")

    def get_billing_groups(self):
        return self.verify(self.get, "/billing-group", result_key="billing_groups")

    def get_billing_group(self, billing_group):
        return self.verify(self.get, self.build_path("billing-group", billing_group), result_key="billing_group")

    def get_billing_group_projects(self, billing_group):
        return self.verify(self.get, self.build_path("billing-group", billing_group, "projects"), result_key="projects")

    def update_billing_group(
        self,
        billing_group,
        *,
        billing_group_name=None,
        account_id=None,
        card_id=None,
        vat_id=None,
        billing_currency=None,
        billing_extra_text=None,
        billing_emails=None,
        company=None,
        address_lines=None,
        country_code=None,
        city=None,
        state=None,
        zip_code=None,
    ):
        body = {}
        if billing_group_name is not None:
            body["billing_group_name"] = billing_group_name
        if account_id is not None:
            body["account_id"] = account_id
        if card_id is not None:
            body["card_id"] = card_id
        if vat_id is not None:
            body["vat_id"] = vat_id
        if billing_currency is not None:
            body["billing_currency"] = billing_currency
        if billing_extra_text is not None:
            body["billing_extra_text"] = billing_extra_text
        if billing_emails is not None:
            body["billing_emails"] = [{"email": email} for email in billing_emails]
        if company is not None:
            body["company"] = company
        if address_lines is not None:
            body["address_lines"] = address_lines
        if country_code is not None:
            body["country_code"] = country_code
        if city is not None:
            body["city"] = city
        if state is not None:
            body["state"] = state
        if zip_code is not None:
            body["zip_code"] = zip_code

        return self.verify(self.put, self.build_path("billing-group", billing_group), body=body, result_key="billing_group")

    def delete_billing_group(self, billing_group):
        return self.verify(self.delete, self.build_path("billing-group", billing_group))

    def assign_projects_to_billing_group(self, billing_group, *, project_names):
        body = {"projects_names": project_names}
        self.verify(self.post, self.build_path("billing-group", billing_group, "projects-assign"), body=body)

    def get_billing_group_events(self, billing_group, *, limit=100):
        return self.verify(
            self.get,
            self.build_path("billing-group", billing_group, "events"),
            params={"limit": limit},
            result_key="events"
        )

    def list_billing_group_credits(self, billing_group):
        return self.verify(
            self.get,
            self.build_path("billing-group", billing_group, "credits"),
            result_key="credits",
        )

    def claim_billing_group_credit(self, billing_group, *, credit_code):
        return self.verify(
            self.post,
            self.build_path("billing-group", billing_group, "credits"),
            body={"code": credit_code},
            result_key="credit",
        )

    def list_billing_group_invoices(self, billing_group, *, sort=None):
        params = {"sort": sort} if sort else {}
        invoices = self.verify(
            self.get, self.build_path("billing-group", billing_group, "invoice"), params=params, result_key="invoices"
        )
        for invoice in invoices:
            if invoice.get("download_cookie"):
                invoice["download"] = self.base_url + self.api_prefix + self.build_path(
                    "billing-group", billing_group, "invoice", invoice["invoice_number"], invoice["download_cookie"]
                )
        return invoices

    def get_billing_group_invoice_lines(self, billing_group, invoice_number):
        return self.verify(
            self.get,
            self.build_path("billing-group", billing_group, "invoice", invoice_number, "lines"),
            result_key="lines"
        )

    def start_service_maintenance(self, project, service):
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service, "maintenance", "start"),
        )

    def create_ticket(self, project, severity, title, description, service=None):
        body = {
            "severity": severity,
            "title": title,
            "description": description,
        }
        if service:
            body["service_name"] = service

        return self.verify(self.post, self.build_path("project", project, "tickets"), body=body)

    def list_tickets(self, project):
        return self.verify(self.get, self.build_path("project", project, "tickets"))

    def get_service_migration_status(self, project, service):
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "migration"),
        )

    def list_teams(self, account_id):
        return self.verify(
            self.get,
            self.build_path("account", account_id, "teams"),
            result_key="teams",
        )

    def create_team(self, account_id, team_name):
        return self.verify(
            self.post,
            self.build_path("account", account_id, "teams"),
            body={"team_name": team_name},
        )

    def delete_team(self, account_id, team_id):
        return self.verify(self.delete, self.build_path("account", account_id, "team", team_id))

    def list_team_members(self, account_id, team_id):
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "members"),
            result_key="members",
        )

    def add_team_member(self, account_id, team_id, email):
        return self.verify(
            self.post,
            self.build_path("account", account_id, "team", team_id, "members"),
            body={"email": email},
        )

    def list_team_invites(self, account_id, team_id):
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "invites"),
            result_key="account_invites",
        )

    def delete_team_member(self, account_id, team_id, user_id):
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "team", team_id, "member", user_id),
        )

    def list_team_projects(self, account_id, team_id):
        return self.verify(
            self.get,
            self.build_path("account", account_id, "team", team_id, "projects"),
            result_key="projects",
        )

    def attach_team_to_project(self, account_id, team_id, project, team_type):
        return self.verify(
            self.post,
            self.build_path("account", account_id, "team", team_id, "project", project),
            body={"team_type": team_type},
        )

    def detach_team_from_project(self, account_id, team_id, project):
        return self.verify(
            self.delete,
            self.build_path("account", account_id, "team", team_id, "project", project),
        )
