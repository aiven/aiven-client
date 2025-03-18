# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from .common import UNDEFINED
from aiven.client.base_client import AivenClientBase, Tag
from requests_toolbelt import MultipartEncoder  # type: ignore
from typing import Any, BinaryIO, Collection, Mapping, Sequence, TYPE_CHECKING

import re
import warnings

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass

UNCHANGED = object()  # used as a sentinel value


class AivenCommonClient(AivenClientBase):
    """Aiven Client with high-level operations"""

    def get_service_versions(self) -> Sequence[Mapping[str, str]]:
        return self.verify(self.get, "/service_versions", result_key="service_versions")

    def get_service_indexes(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "index"),
            result_key="indexes",
        )

    def delete_service_index(self, project: str, service: str, index_name: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "index", index_name),
        )

    def get_clouds(self, project: str | None) -> Sequence[dict[str, Any]]:
        if project is None:
            path = "/clouds"
        else:
            path = self.build_path("project", project, "clouds")
        return self.verify(self.get, path, result_key="clouds")

    def get_service(self, project: str, service: str) -> dict[str, Any]:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service),
            result_key="service",
        )

    def get_service_metrics(self, project: str, service: str, period: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "metrics")
        return self.verify(self.post, path, result_key="metrics", body={"period": period})

    def create_service_connection_pool(
        self,
        project: str,
        service: str,
        pool_name: str,
        dbname: str,
        username: str | None = None,
        pool_size: int | None = None,
        pool_mode: str | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {"database": dbname, "pool_name": pool_name}
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
        project: str,
        service: str,
        pool_name: str,
        dbname: str | None = None,
        username: object | str = UNCHANGED,
        pool_size: int | None = None,
        pool_mode: str | None = None,
    ) -> Mapping:
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

    def delete_service_connection_pool(self, project: str, service: str, pool_name: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "connection_pool", pool_name)
        return self.verify(self.delete, path)

    def create_service_database(self, project: str, service: str, dbname: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "db"),
            body={"database": dbname},
        )

    def delete_service_database(self, project: str, service: str, dbname: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "db", dbname)
        return self.verify(self.delete, path)

    def list_databases(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "db")
        return self.verify(self.get, path)

    def create_service_user(
        self, project: str, service: str, username: str, extra_params: Mapping[str, Any] | None = None
    ) -> Mapping:
        body = {"username": username}
        if extra_params:
            body.update(extra_params)
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "user"),
            body=body,
            result_key="user",
        )

    def delete_service_user(self, project: str, service: str, username: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "user", username)
        return self.verify(self.delete, path)

    def get_service_user(self, project: str, service: str, username: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "user", username)
        return self.verify(self.get, path, result_key="user")

    def acknowledge_service_user_certificate(self, project: str, service: str, username: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "acknowledge-renewal"}
        return self.verify(self.put, path, body=body)

    def reset_service_user_password(self, project: str, service: str, username: str, password: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "reset-credentials"}
        if password is not None:
            body["new_password"] = password
        return self.verify(self.put, path, body=body)

    def set_service_user_access_control(
        self, project: str, service: str, username: str, access_control: Mapping[str, Any]
    ) -> Mapping:
        path = self.build_path("project", project, "service", service, "user", username)
        body = {"operation": "set-access-control", "access_control": access_control}
        return self.verify(self.put, path, body=body)

    def get_service_integration_endpoint(
        self,
        *,
        project: str,
        endpoint_id: str,
        include_secrets: bool = False,
    ) -> dict[str, Any]:
        include_secrets_str = "true" if include_secrets else "false"
        path = self.build_path("project", project, "integration_endpoint", endpoint_id)
        return self.verify(
            self.get,
            path,
            params={"include_secrets": include_secrets_str},
            result_key="service_integration_endpoint",
        )

    def get_service_integration_endpoints(self, project: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "integration_endpoint")
        return self.verify(self.get, path, result_key="service_integration_endpoints")

    def get_service_integration_endpoint_types(self, project: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "integration_endpoint_types")
        return self.verify(self.get, path, result_key="endpoint_types")

    def create_service_integration_endpoint(
        self, project: str, endpoint_name: str, endpoint_type: str, user_config: Mapping[str, Any]
    ) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "integration_endpoint"),
            body={
                "endpoint_name": endpoint_name,
                "endpoint_type": endpoint_type,
                "user_config": user_config,
            },
        )

    def update_service_integration_endpoint(self, project: str, endpoint_id: str, user_config: Mapping[str, Any]) -> Mapping:
        return self.verify(
            self.put,
            self.build_path("project", project, "integration_endpoint", endpoint_id),
            body={
                "user_config": user_config,
            },
        )

    def delete_service_integration_endpoint(self, project: str, endpoint_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "integration_endpoint", endpoint_id),
        )

    def get_service_backups(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "service", service, "backups")
        return self.verify(self.get, path, result_key="backups")

    def get_service_integrations(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "service", service, "integration")
        return self.verify(self.get, path, result_key="service_integrations")

    def get_service_integration_types(self, project: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "integration_types")
        return self.verify(self.get, path, result_key="integration_types")

    def create_service_integration(
        self,
        project: str,
        integration_type: str,
        source_service: str | None = None,
        dest_service: str | None = None,
        source_endpoint_id: str | None = None,
        dest_endpoint_id: str | None = None,
        user_config: Mapping[str, Any] | None = None,
    ) -> Mapping:
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

    def update_service_integration(self, project: str, integration_id: str, user_config: Mapping[str, Any]) -> Mapping:
        return self.verify(
            self.put,
            self.build_path("project", project, "integration", integration_id),
            body={
                "user_config": user_config,
            },
            result_key="service_integration",
        )

    def get_service_integration(self, project: str, integration_id: str) -> Mapping:
        path = self.build_path("project", project, "integration", integration_id)
        return self.verify(self.get, path, result_key="service_integration")

    def delete_service_integration(self, project: str, integration_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "integration", integration_id),
        )

    def create_service_task(self, project: str, service: str, body: Mapping[str, Any]) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "task"),
            body=body,
        )

    def get_service_task(self, project: str, service: str, task_id: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "task", task_id)
        return self.verify(self.get, path, result_key="task")

    def get_service_topic(self, project: str, service: str, topic: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "topic", topic)
        return self.verify(self.get, path, result_key="topic")

    def _set_namespace_options(
        self,
        ns: dict[str, Any],
        ns_ret: str | None = None,
        ns_res: str | None = None,
        ns_blocksize_dur: str | None = None,
        ns_block_data_expiry_dur: str | None = None,
        ns_buffer_future_dur: str | None = None,
        ns_buffer_past_dur: str | None = None,
        ns_writes_to_commitlog: bool | None = None,
    ) -> None:
        re_ns_duration = re.compile(r"\d+[smhd]")

        def _validate_ns_dur(val: str) -> None:
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

    def list_m3_namespaces(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        service_res = self.get_service(project=project, service=service)
        return service_res.get("user_config", {}).get("namespaces", [])

    def delete_m3_namespace(self, project: str, service: str, ns_name: str) -> Mapping:
        service_res = self.get_service(project=project, service=service)
        old_namespaces = service_res.get("user_config", {}).get("namespaces", [])
        new_namespaces = [ns for ns in old_namespaces if ns["name"] != ns_name]
        if len(old_namespaces) == len(new_namespaces):
            raise KeyError(f"Namespace '{ns_name}' does not exist")
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {"namespaces": new_namespaces}},
        )

    def add_m3_namespace(
        self,
        project: str,
        service: str,
        ns_name: str,
        ns_type: str,
        ns_ret: str,
        ns_res: str | None = None,
        ns_blocksize_dur: str | None = None,
        ns_block_data_expiry_dur: str | None = None,
        ns_buffer_future_dur: str | None = None,
        ns_buffer_past_dur: str | None = None,
        ns_writes_to_commitlog: bool | None = None,
    ) -> Mapping:
        service_res = self.get_service(project=project, service=service)
        namespaces = service_res.get("user_config", {}).get("namespaces", [])
        valid_namespace_types = {"unaggregated", "aggregated"}
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
            ns_writes_to_commitlog=ns_writes_to_commitlog,
        )
        namespaces.append(new_namespace)
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {"namespaces": namespaces}},
        )

    def update_m3_namespace(
        self,
        project: str,
        service: str,
        ns_name: str,
        ns_ret: str | None = None,
        ns_res: str | None = None,
        ns_blocksize_dur: str | None = None,
        ns_block_data_expiry_dur: str | None = None,
        ns_buffer_future_dur: str | None = None,
        ns_buffer_past_dur: str | None = None,
        ns_writes_to_commitlog: bool | None = None,
    ) -> Mapping:
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
            ns_writes_to_commitlog=ns_writes_to_commitlog,
        )
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service),
            body={"user_config": {"namespaces": namespaces}},
        )

    def list_service_topics(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "topic"),
            result_key="topics",
        )

    def create_service_topic(
        self,
        project: str,
        service: str,
        topic: str,
        partitions: int,
        replication: int,
        min_insync_replicas: int,
        retention_bytes: int,
        retention_hours: int,
        cleanup_policy: str,
        retention_ms: int | None = None,
        remote_storage_enable: bool | None = None,
        local_retention_ms: int | None = None,
        local_retention_bytes: int | None = None,
        tags: Sequence[Tag] | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {
            "cleanup_policy": cleanup_policy,
            "min_insync_replicas": min_insync_replicas,
            "topic_name": topic,
            "partitions": partitions,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        }
        config = {}
        if retention_ms is not None:
            config["retention_ms"] = retention_ms
        if remote_storage_enable is not None:
            config["remote_storage_enable"] = remote_storage_enable
        if local_retention_ms is not None:
            config["local_retention_ms"] = local_retention_ms
        if local_retention_bytes is not None:
            config["local_retention_bytes"] = local_retention_bytes
        if config:
            body["config"] = config

        if tags is not None:
            body.update({"tags": tags})
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "topic"),
            body=body,
        )

    def update_service_topic(
        self,
        project: str,
        service: str,
        topic: str,
        partitions: int,
        retention_bytes: int,
        retention_hours: int,
        min_insync_replicas: int,
        retention_ms: int | None = None,
        remote_storage_enable: bool | None = None,
        local_retention_ms: int | None = None,
        local_retention_bytes: int | None = None,
        replication: int | None = None,
        tags: Sequence[str] | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {
            "partitions": partitions,
            "min_insync_replicas": min_insync_replicas,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        }
        config = {}
        if retention_ms is not None:
            config["retention_ms"] = retention_ms
        if remote_storage_enable is not None:
            config["remote_storage_enable"] = remote_storage_enable
        if local_retention_ms is not None:
            config["local_retention_ms"] = local_retention_ms
        if local_retention_bytes is not None:
            config["local_retention_bytes"] = local_retention_bytes
        if config:
            body["config"] = config

        if tags is not None:
            body.update({"tags": tags})
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service, "topic", topic),
            body=body,
        )

    def delete_service_topic(self, project: str, service: str, topic: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "topic", topic),
        )

    def list_service_elasticsearch_acl_config(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "elasticsearch", "acl"),
        )

    @staticmethod
    def _add_es_acl_rules(config: dict[str, Any], user: str | None, rules: Mapping[str, Any]) -> None:
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
    def _del_es_acl_rules(config: dict[str, Any], user: str | None, rules: set[str]) -> None:
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
        project: str,
        service: str,
        enabled: bool | None = None,
        extended_acl: bool | None = None,
        username: str | None = None,
        add_rules: Sequence[str] | None = None,
        del_rules: Sequence[str] | None = None,
    ) -> Mapping:
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

    def opensearch_security_get(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "opensearch", "security"),
        )

    def opensearch_security_set(self, project: str, service: str, password: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "opensearch", "security", "admin"),
            body={"admin_password": password},
        )

    def opensearch_security_reset(self, project: str, service: str, old_password: str, new_password: str) -> Mapping:
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service, "opensearch", "security", "admin"),
            body={"admin_password": old_password, "new_password": new_password},
        )

    def add_service_kafka_acl(self, project: str, service: str, permission: str, topic: str, username: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "acl"),
            body={
                "permission": permission,
                "topic": topic,
                "username": username,
            },
        )

    def add_service_kafka_schema_registry_acl(
        self,
        project: str,
        service: str,
        permission: str,
        resource: str,
        username: str,
    ) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "kafka", "schema-registry", "acl"),
            body={
                "permission": permission,
                "resource": resource,
                "username": username,
            },
        )

    def create_connector_config_based_on_current(
        self, project: str, service: str, connector_name: str, config_update: Mapping[str, Any]
    ) -> Mapping:
        current_connectors = self.list_kafka_connectors(project, service)
        connector = [conn for conn in current_connectors["connectors"] if conn["name"] == connector_name]
        if not connector:
            raise KeyError("Current configuration for connector '{}' not in connector list".format(connector_name))
        assert len(connector) == 1
        full_config = connector[0]["config"]
        full_config.update(config_update)
        return full_config

    def delete_service_kafka_acl(self, project: str, service: str, acl_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "acl", acl_id),
        )

    def delete_service_kafka_schema_registry_acl(self, project: str, service: str, acl_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "kafka", "schema-registry", "acl", acl_id),
        )

    def get_available_kafka_connectors(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "available-connectors"),
        )

    def list_kafka_connectors(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "connectors"),
        )

    def get_kafka_connector_status(self, project: str, service: str, connector_name: str) -> Mapping:
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

    def get_kafka_connector_schema(self, project: str, service: str, connector_name: str) -> Mapping:
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

    def create_kafka_connector(self, project: str, service: str, config: Mapping[str, Any]) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "connectors"),
            body=config,
        )

    def update_kafka_connector(
        self, project: str, service: str, connector_name: str, config: Mapping[str, Any], fetch_current: bool = False
    ) -> Mapping:
        path = self.build_path("project", project, "service", service, "connectors", connector_name)
        if fetch_current:
            config = self.create_connector_config_based_on_current(project, service, connector_name, config)
        return self.verify(self.put, path, body=config)

    def delete_kafka_connector(self, project: str, service: str, connector_name: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "connectors", connector_name)
        return self.verify(self.delete, path)

    def pause_kafka_connector(self, project: str, service: str, connector_name: str) -> Mapping:
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

    def resume_kafka_connector(self, project: str, service: str, connector_name: str) -> Mapping:
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

    def restart_kafka_connector(self, project: str, service: str, connector_name: str) -> Mapping:
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

    def restart_kafka_connector_task(self, project: str, service: str, connector_name: str, task_id: str) -> Mapping:
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

    def get_schema(self, project: str, service: str, schema_id: str) -> Mapping:
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

    def check_schema_compatibility(self, project: str, service: str, subject: str, version: str, schema: str) -> Mapping:
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

    def get_schema_global_configuration(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config")
        return self.verify(self.get, path)

    def update_schema_global_configuration(self, project: str, service: str, compatibility: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config")
        return self.verify(self.put, path, body={"compatibility": compatibility})

    def get_schema_subject_configuration(self, project: str, service: str, subject: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config", subject)
        return self.verify(self.get, path)

    def update_schema_subject_configuration(self, project: str, service: str, subject: str, compatibility: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kafka", "schema", "config", subject)
        return self.verify(self.put, path, body={"compatibility": compatibility})

    def list_schema_subjects(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kafka", "schema", "subjects")
        return self.verify(self.get, path)

    def delete_schema_subject(self, project: str, service: str, subject: str) -> Mapping:
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

    def get_schema_subject_version(self, project: str, service: str, subject: str, version: str) -> Mapping:
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

    def get_schema_subject_version_schema(self, project: str, service: str, subject: str, version: str) -> Mapping:
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

    def list_schema_subject_versions(self, project: str, service: str, subject: str) -> Mapping:
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

    def create_schema_subject_version(self, project: str, service: str, subject: str, schema: str) -> Mapping:
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

    def delete_schema_subject_version(self, project: str, service: str, subject: str, version: str) -> Mapping:
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

    def list_mirrormaker_replication_flows(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "service", service, "mirrormaker", "replication-flows")
        return self.verify(self.get, path, result_key="replication_flows")

    def create_mirrormaker_replication_flow(
        self, project: str, service: str, source_cluster: str, target_cluster: str, config: Mapping[str, Any]
    ) -> Mapping:
        path = self.build_path("project", project, "service", service, "mirrormaker", "replication-flows")
        body: dict[str, Any] = {}
        body.update(config)
        body["source_cluster"] = source_cluster
        body["target_cluster"] = target_cluster
        return self.verify(self.post, path, body=body)

    def update_mirrormaker_replication_flow(
        self, project: str, service: str, source_cluster: str, target_cluster: str, config: Mapping[str, Any]
    ) -> Mapping:
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
        body: dict[str, Any] = {}
        body.update(config)
        return self.verify(self.put, path, body=body, result_key="replication_flow")

    def get_mirrormaker_replication_flow(
        self, project: str, service: str, source_cluster: str, target_cluster: str
    ) -> Mapping:
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

    def delete_mirrormaker_replication_flow(
        self, project: str, service: str, source_cluster: str, target_cluster: str
    ) -> Mapping:
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

    def list_project_vpcs(self, project: str) -> Mapping:
        return self.verify(self.get, self.build_path("project", project, "vpcs"))

    def create_project_vpc(self, project: str, cloud: str, network_cidr: str, peering_connections: Sequence) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "vpcs"),
            body={
                "cloud_name": cloud,
                "network_cidr": network_cidr,
                "peering_connections": peering_connections,
            },
        )

    def request_project_vpc(self, project: str, cloud: str, network_cidr: str, peering_connections: Sequence) -> Mapping:
        warnings.warn("Use the create_project_vpc method", DeprecationWarning)
        return self.create_project_vpc(
            project=project,
            cloud=cloud,
            network_cidr=network_cidr,
            peering_connections=peering_connections,
        )

    def get_project_vpc(self, project: str, project_vpc_id: str) -> Mapping:
        return self.verify(self.get, self.build_path("project", project, "vpcs", project_vpc_id))

    def delete_project_vpc(self, project: str, project_vpc_id: str) -> Mapping:
        return self.verify(self.delete, self.build_path("project", project, "vpcs", project_vpc_id))

    def create_project_vpc_peering_connection(
        self,
        project: str,
        project_vpc_id: str,
        peer_cloud_account: str,
        peer_vpc: str,
        peer_region: str | None = None,
        peer_resource_group: str | None = None,
        peer_azure_app_id: str | None = None,
        peer_azure_tenant_id: str | None = None,
        user_peer_network_cidrs: Collection[str] | None = None,
    ) -> Mapping:
        path = self.build_path("project", project, "vpcs", project_vpc_id, "peering-connections")
        body: dict[str, Any] = {
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

    def request_project_vpc_peering_connection(
        self, project: str, project_vpc_id: str, peer_cloud_account: str, peer_vpc: str
    ) -> Mapping:
        warnings.warn("Use the create_project_vpc_peering_connection method", DeprecationWarning)
        return self.create_project_vpc_peering_connection(
            project=project,
            project_vpc_id=project_vpc_id,
            peer_cloud_account=peer_cloud_account,
            peer_vpc=peer_vpc,
        )

    def delete_project_vpc_peering_connection(
        self,
        project: str,
        project_vpc_id: str,
        peer_cloud_account: str,
        peer_vpc: str,
        peer_region: str | None = None,
        peer_resource_group: object | str = UNDEFINED,
    ) -> Mapping:
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
            path += self.build_path("peer-resource-groups", str(peer_resource_group))
        path += self.build_path("peer-vpcs", peer_vpc)
        if peer_region is not None:
            path += self.build_path("peer-regions", peer_region)
        return self.verify(self.delete, path)

    def get_project_vpc_peering_connection(
        self,
        project: str,
        project_vpc_id: str,
        peer_cloud_account: str,
        peer_vpc: str,
        peer_region: object | str = UNDEFINED,
        peer_resource_group: object | str = UNDEFINED,
    ) -> dict:
        vpc = self.get_project_vpc(project=project, project_vpc_id=project_vpc_id)
        for peering_connection in vpc["peering_connections"]:
            if (
                peering_connection["peer_cloud_account"] == peer_cloud_account
                and peering_connection["peer_vpc"] == peer_vpc
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

    def update_project_vpc_user_peer_network_cidrs(
        self,
        project: str,
        project_vpc_id: str,
        add: Sequence[Mapping[str, str]] | None = None,
        delete: Sequence[str] | None = None,
    ) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "vpcs",
            project_vpc_id,
            "user-peer-network-cidrs",
        )
        body: dict[str, Any] = {}
        if add:
            body["add"] = add
        if delete:
            body["delete"] = delete
        return self.verify(self.put, path, body=body)

    def list_project_tags(self, project: str) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        return self.verify(self.get, path)

    def update_project_tags(self, project: str, tag_updates: Mapping[str, str | None]) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        body = {"tags": tag_updates}
        return self.verify(self.patch, path, body=body)

    def replace_project_tags(self, project: str, tags: Mapping[str, str]) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "tags",
        )
        body = {"tags": tags}
        return self.verify(self.put, path, body=body)

    def get_project_sbom_download_url(self, project: str, output_format: str) -> Mapping[str, str]:
        path = self.build_path("project", project, "generate-sbom-download-url", output_format)
        return self.verify(self.get, path)

    def create_service(
        self,
        project: str,
        service: str,
        service_type: str,
        plan: str,
        disk_space_mb: int | None = None,
        cloud: str | None = None,
        user_config: Mapping[str, Any] | None = None,
        project_vpc_id: object | str = UNDEFINED,
        service_integrations: Sequence[Mapping[str, str]] | None = None,
        termination_protection: bool = False,
        static_ips: tuple[str, ...] = (),
    ) -> Mapping:
        user_config = user_config or {}
        body: dict[str, Any] = {
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
        project: str,
        service: str,
        cloud: str | None = None,
        maintenance: Mapping[str, Any] | None = None,
        user_config: Mapping[str, Any] | None = None,
        plan: str | None = None,
        disk_space_mb: int | None = None,
        karapace: bool | None = None,
        powered: bool | None = None,
        termination_protection: bool | None = None,
        project_vpc_id: object | str = UNDEFINED,
        schema_registry_authorization: bool | None = None,
    ) -> Mapping:
        user_config = user_config or {}
        body: dict[str, Any] = {}
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
        if schema_registry_authorization is not None:
            body["schema_registry_authz"] = schema_registry_authorization
        path = self.build_path("project", project, "service", service)
        return self.verify(self.put, path, body=body, result_key="service")

    def reset_service_credentials(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "credentials", "reset")
        return self.verify(self.put, path, result_key="service")

    def _static_ip_address_path(self, project: str, *parts: str) -> str:
        return self.build_path("project", project, "static-ips", *parts)

    def list_static_ip_addresses(self, project: str) -> Sequence[dict[str, Any]]:
        path = self._static_ip_address_path(project)
        return self.verify(self.get, path, result_key="static_ips", params={"limit": 999})

    def create_static_ip_address(self, project: str, cloud_name: str) -> Mapping:
        path = self._static_ip_address_path(project)
        return self.verify(self.post, path, body={"cloud_name": cloud_name})

    def associate_static_ip_address(self, project: str, static_ip_id: str, service_name: str) -> Mapping:
        path = self._static_ip_address_path(project, static_ip_id, "association")
        return self.verify(self.post, path, body={"service_name": service_name})

    def dissociate_static_ip_address(self, project: str, static_ip_id: str) -> Mapping:
        path = self._static_ip_address_path(project, static_ip_id, "association")
        return self.verify(self.delete, path)

    def delete_static_ip_address(self, project: str, static_ip_id: str) -> Mapping:
        path = self._static_ip_address_path(project, static_ip_id)
        return self.verify(self.delete, path)

    def delete_service(self, project: str, service: str) -> Mapping:
        return self.verify(self.delete, self.build_path("project", project, "service", service))

    def get_pg_service_current_queries(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        warnings.warn("Use the get_service_current_queries method", DeprecationWarning)
        return self.get_service_current_queries(project, service)

    def get_pg_service_query_stats(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        warnings.warn("Use the get_service_query_stats method", DeprecationWarning)
        return self.get_service_query_stats(project, service, service_type="pg")

    def reset_pg_service_query_stats(self, project: str, service: str) -> Mapping:
        warnings.warn("Use the reset_service_query_stats method", DeprecationWarning)
        return self.reset_service_query_stats(project, service)

    def get_service_current_queries(self, project: str, service: str) -> Sequence[dict[str, Any]]:
        path = self.build_path("project", project, "service", service, "query", "activity")
        return self.verify(
            self.post,
            path,
            result_key="queries",
            body={"limit": 100, "order_by": "query_duration:desc"},
        )

    def get_service_query_stats(
        self, project: str, service: str, service_type: str | None = None
    ) -> Sequence[dict[str, Any]]:
        if service_type is None:
            service_type = self.get_service(project, service)["service_type"]

        # Currently, `alloydbomni` query stats are also exposed under `/pg/query/stats`.
        if service_type == "alloydbomni":
            service_type = "pg"

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

    def reset_service_query_stats(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "query", "stats", "reset")
        return self.verify(self.put, path, result_key="queries")

    def list_service_tags(self, project: str, service: str) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        return self.verify(self.get, path)

    def update_service_tags(self, project: str, service: str, tag_updates: Mapping[str, str | None]) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        body = {"tags": tag_updates}
        return self.verify(self.patch, path, body=body)

    def replace_service_tags(self, project: str, service: str, tags: Mapping[str, str]) -> Mapping:
        path = self.build_path(
            "project",
            project,
            "service",
            service,
            "tags",
        )
        body = {"tags": tags}
        return self.verify(self.put, path, body=body)

    def get_services(self, project: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("project", project, "service"),
            result_key="services",
        )

    def get_service_types(self, project: str | None) -> Mapping:
        if project is None:
            path = "/service_types"
        else:
            path = self.build_path("project", project, "service_types")
        return self.verify(self.get, path, result_key="service_types")

    def create_project(
        self,
        project: str,
        account_id: str | None = None,
        billing_group_id: str | None = None,
        cloud: str | None = None,
        copy_from_project: str | None = None,
        tech_emails: Sequence[str] | None = None,
        use_source_project_billing_group: bool | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {
            "cloud": cloud,
            "project": project,
        }
        if account_id is not None:
            body["account_id"] = account_id
        if billing_group_id is not None:
            body["billing_group_id"] = billing_group_id
        if copy_from_project is not None:
            body["copy_from_project"] = copy_from_project
        if tech_emails is not None:
            body["tech_emails"] = [{"email": email} for email in tech_emails]
        if use_source_project_billing_group is not None:
            body["use_source_project_billing_group"] = use_source_project_billing_group

        return self.verify(self.post, "/project", body=body, result_key="project")

    def delete_project(self, project: str) -> Mapping:
        return self.verify(self.delete, self.build_path("project", project))

    def get_project(self, project: str) -> Mapping:
        return self.verify(self.get, self.build_path("project", project), result_key="project")

    def get_projects(self) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, "/project", result_key="projects")

    def update_project(
        self,
        project: str,
        new_project_name: str | None = None,
        account_id: str | None = None,
        cloud: str | None = None,
        tech_emails: Sequence[str] | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {}
        if new_project_name is not None:
            body["project_name"] = new_project_name
        if account_id is not None:
            body["account_id"] = account_id
        if cloud is not None:
            body["cloud"] = cloud
        if tech_emails is not None:
            body["tech_emails"] = [{"email": email} for email in tech_emails]

        return self.verify(
            self.put,
            self.build_path("project", project),
            body=body,
            result_key="project",
        )

    def get_project_ca(self, project: str) -> Mapping:
        return self.verify(self.get, self.build_path("project", project, "kms", "ca"))

    def get_service_ca(self, project: str, service: str, ca: str) -> dict:
        path = self.build_path("project", project, "service", service, "kms", "ca", ca)
        return self.verify(self.get, path)

    def get_service_keypair(self, project: str, service: str, keypair: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "kms", "keypairs", keypair)
        return self.verify(self.get, path)

    def invite_project_user(self, project: str, user_email: str, member_type: str | None = None) -> Mapping:
        body = {
            "user_email": user_email,
        }
        if member_type is not None:
            body["member_type"] = member_type
        return self.verify(self.post, self.build_path("project", project, "invite"), body=body)

    def remove_project_user(self, project: str, user_email: str) -> Mapping:
        return self.verify(self.delete, self.build_path("project", project, "user", user_email))

    def list_project_users(self, project: str) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, self.build_path("project", project, "users"), result_key="users")

    def list_invited_project_users(self, project: str) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, self.build_path("project", project, "users"), result_key="invitations")

    def get_service_logs(
        self, project: str, service: str, sort_order: str | None = None, offset: str | None = None, limit: int = 100
    ) -> Mapping:
        body: dict[str, Any] = {"limit": limit}
        if offset is not None:
            body["offset"] = str(offset)
        if sort_order is not None:
            body["sort_order"] = sort_order
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "logs"),
            body=body,
        )

    def get_events(self, project: str, limit: int = 100) -> Sequence[dict[str, Any]]:
        params = {"limit": limit}
        return self.verify(
            self.get,
            self.build_path("project", project, "events"),
            params=params,
            result_key="events",
        )

    def get_stripe_key(self) -> str:
        return self.verify(self.get, self.build_path("config", "stripe_key"), result_key="stripe_key")

    def list_project_credits(self, project: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("project", project, "credits"),
            result_key="credits",
        )

    def claim_project_credit(self, project: str, credit_code: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "credits"),
            body={"code": credit_code},
            result_key="credit",
        )

    def create_billing_group(
        self,
        billing_group_name: str,
        *,
        account_id: str | None = None,
        card_id: str | None = None,
        vat_id: str | None = None,
        billing_currency: str | None = None,
        billing_extra_text: str | None = None,
        billing_emails: str | None = None,
        company: str | None = None,
        address_lines: Sequence[str] | None = None,
        country_code: str | None = None,
        city: str | None = None,
        state: str | None = None,
        zip_code: str | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {"billing_group_name": billing_group_name}
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

    def get_billing_groups(self) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, "/billing-group", result_key="billing_groups")

    def get_billing_group(self, billing_group: str) -> Mapping:
        return self.verify(self.get, self.build_path("billing-group", billing_group), result_key="billing_group")

    def get_billing_group_projects(self, billing_group: str) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, self.build_path("billing-group", billing_group, "projects"), result_key="projects")

    def update_billing_group(  # noqa: PLR0912
        self,
        billing_group: str,
        *,
        billing_group_name: str | None = None,
        account_id: str | None = None,
        card_id: str | None = None,
        vat_id: str | None = None,
        billing_currency: str | None = None,
        billing_extra_text: str | None = None,
        billing_emails: str | None = None,
        company: str | None = None,
        address_lines: Sequence[str] | None = None,
        country_code: str | None = None,
        city: str | None = None,
        state: str | None = None,
        zip_code: str | None = None,
    ) -> Mapping:
        body: dict[str, Any] = {}
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

    def delete_billing_group(self, billing_group: str) -> Mapping:
        return self.verify(self.delete, self.build_path("billing-group", billing_group))

    def assign_projects_to_billing_group(self, billing_group: str, *, project_names: Sequence[str]) -> Mapping:
        body = {"projects_names": project_names}
        return self.verify(self.post, self.build_path("billing-group", billing_group, "projects-assign"), body=body)

    def get_billing_group_events(self, billing_group: str, *, limit: int = 100) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get, self.build_path("billing-group", billing_group, "events"), params={"limit": limit}, result_key="events"
        )

    def list_billing_group_credits(self, billing_group: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get,
            self.build_path("billing-group", billing_group, "credits"),
            result_key="credits",
        )

    def claim_billing_group_credit(self, billing_group: str, *, credit_code: str) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("billing-group", billing_group, "credits"),
            body={"code": credit_code},
            result_key="credit",
        )

    def list_billing_group_invoices(self, billing_group: str, *, sort: str | None = None) -> Sequence[dict[str, Any]]:
        params = {"sort": sort} if sort else {}
        invoices = self.verify(
            self.get, self.build_path("billing-group", billing_group, "invoice"), params=params, result_key="invoices"
        )
        for invoice in invoices:
            if invoice.get("download_cookie"):
                invoice["download"] = (
                    self.base_url
                    + self.api_prefix
                    + self.build_path(
                        "billing-group", billing_group, "invoice", invoice["invoice_number"], invoice["download_cookie"]
                    )
                )
        return invoices

    def get_billing_group_invoice_lines(self, billing_group: str, invoice_number: str) -> Sequence[dict[str, Any]]:
        return self.verify(
            self.get, self.build_path("billing-group", billing_group, "invoice", invoice_number, "lines"), result_key="lines"
        )

    def start_service_maintenance(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.put,
            self.build_path("project", project, "service", service, "maintenance", "start"),
        )

    def create_ticket(
        self, project: str, severity: str, title: str, description: str, service: str | None = None
    ) -> Mapping:
        body = {
            "severity": severity,
            "title": title,
            "description": description,
        }
        if service:
            body["service_name"] = service

        return self.verify(self.post, self.build_path("project", project, "tickets"), body=body)

    def list_tickets(self, project: str) -> Mapping:
        return self.verify(self.get, self.build_path("project", project, "tickets"))

    def get_service_migration_status(self, project: str, service: str) -> Mapping:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "migration"),
        )

    def custom_file_list(self, project: str, service: str) -> Mapping:
        path = self.build_path("project", project, "service", service, "file")
        return self.verify(self.get, path)

    def custom_file_get(self, project: str, service: str, file_id: str) -> bytes:
        path = self.build_path("project", project, "service", service, "file", file_id)
        return self.verify(self.get, path)

    def custom_file_upload(
        self,
        project: str,
        service: str,
        file_type: str,
        file_object: BinaryIO,
        file_name: str,
        update: bool = False,
    ) -> Mapping:
        path = self.build_path("project", project, "service", service, "file")
        return self.verify(
            self.post,
            path,
            body=MultipartEncoder(
                fields={
                    "file": (file_name, file_object, "application/octet-stream"),
                    "filetype": file_type,
                    "filename": file_name,
                }
            ),
        )

    def custom_file_update(
        self,
        project: str,
        service: str,
        file_object: BinaryIO,
        file_id: str,
    ) -> Mapping:
        path = self.build_path("project", project, "service", service, "file", file_id)
        return self.verify(
            self.put,
            path,
            body=MultipartEncoder(
                fields={
                    "file": (file_id, file_object, "application/octet-stream"),
                }
            ),
        )

    def flink_list_applications(
        self,
        *,
        project: str,
        service: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
            ),
        )

    def flink_create_application(
        self,
        *,
        project: str,
        service: str,
        application_properties: Mapping[str, Any],
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
            ),
            body=application_properties,
        )

    def flink_get_application(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
            ),
        )

    def flink_update_application(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        application_properties: Mapping[str, str],
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.put,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
            ),
            body=application_properties,
        )

    def flink_delete_application(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.delete,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
            ),
        )

    def flink_create_application_version(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        application_version_properties: Mapping[str, Any],
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "version",
            ),
            body=application_version_properties,
        )

    def flink_validate_application_version(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        application_version_properties: Mapping[str, Any],
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "version",
                "validate",
            ),
            body=application_version_properties,
        )

    def flink_get_application_version(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        application_version_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "version",
                application_version_id,
            ),
        )

    def flink_delete_application_version(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        application_version_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.delete,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "version",
                application_version_id,
            ),
        )

    def flink_list_application_deployments(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
            ),
        )

    def flink_get_application_deployment(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        deployment_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
                deployment_id,
            ),
        )

    def flink_create_application_deployment(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        deployment_properties: Mapping[str, Any],
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
            ),
            body=deployment_properties,
        )

    def flink_delete_application_deployment(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        deployment_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.delete,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
                deployment_id,
            ),
        )

    def flink_stop_application_deployment(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        deployment_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
                deployment_id,
                "stop",
            ),
        )

    def flink_cancel_application_deployment(
        self,
        *,
        project: str,
        service: str,
        application_id: str,
        deployment_id: str,
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "flink",
                "application",
                application_id,
                "deployment",
                deployment_id,
                "cancel",
            ),
        )

    def byoc_create(
        self,
        *,
        organization_id: str,
        deployment_model: str,
        cloud_provider: str,
        cloud_region: str,
        reserved_cidr: str,
        display_name: str,
    ) -> Mapping[Any, Any]:
        body = {
            "deployment_model": deployment_model,
            "cloud_provider": cloud_provider,
            "cloud_region": cloud_region,
            "reserved_cidr": reserved_cidr,
            "display_name": display_name,
        }
        return self.verify(
            self.post, self.build_path("organization", organization_id, "custom-cloud-environments"), body=body
        )

    def byoc_update(
        self,
        *,
        organization_id: str,
        byoc_id: str,
        deployment_model: str | None,
        cloud_provider: str | None,
        cloud_region: str | None,
        reserved_cidr: str | None,
        display_name: str | None,
        tags: Mapping[str, str | None] | None,
    ) -> Mapping[Any, Any]:
        body = {
            key: value
            for key, value in {
                "deployment_model": deployment_model,
                "cloud_provider": cloud_provider,
                "cloud_region": cloud_region,
                "reserved_cidr": reserved_cidr,
                "display_name": display_name,
                "tags": tags,
            }.items()
            if value is not None
        }
        return self.verify(
            self.put,
            self.build_path("organization", organization_id, "custom-cloud-environments", byoc_id),
            body=body,
        )

    def byoc_list(self, *, organization_id: str) -> Mapping[Any, Any]:
        return self.verify(self.get, self.build_path("organization", organization_id, "custom-cloud-environments"))

    def byoc_provision(
        self,
        *,
        organization_id: str,
        byoc_id: str,
        aws_iam_role_arn: str | None = None,
        google_privilege_bearing_service_account_id: str | None = None,
    ) -> Mapping[Any, Any]:
        if aws_iam_role_arn is not None:
            body = {"aws_iam_role_arn": aws_iam_role_arn}
        elif google_privilege_bearing_service_account_id is not None:
            body = {"google_privilege_bearing_service_account_id": google_privilege_bearing_service_account_id}
        else:
            body = {}
        return self.verify(
            self.post,
            self.build_path("organization", organization_id, "custom-cloud-environments", byoc_id, "provision"),
            body=body,
        )

    def byoc_delete(self, *, organization_id: str, byoc_id: str) -> Mapping[Any, Any]:
        return self.verify(
            self.delete,
            self.build_path("organization", organization_id, "custom-cloud-environments", byoc_id),
        )

    def byoc_terraform_get_template(self, *, organization_id: str, byoc_id: str) -> str:
        return self.verify(
            self.get,
            self.build_path(
                "organization",
                organization_id,
                "custom-cloud-environments",
                byoc_id,
                "infra-templates",
                "terraform",
                "template",
            ),
        )["template"]

    def byoc_terraform_get_vars(self, *, organization_id: str, byoc_id: str) -> str:
        return self.verify(
            self.get,
            self.build_path(
                "organization",
                organization_id,
                "custom-cloud-environments",
                byoc_id,
                "infra-templates",
                "terraform",
                "variables",
            ),
        )["variables"]

    def byoc_permissions_get(self, *, organization_id: str, byoc_id: str) -> Mapping[Any, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "organization",
                organization_id,
                "custom-cloud-environments",
                byoc_id,
                "permissions",
            ),
        )

    def byoc_permissions_set(
        self, *, organization_id: str, byoc_id: str, accounts: list[str], projects: list[str]
    ) -> Mapping[Any, Any]:
        return self.verify(
            self.put,
            self.build_path(
                "organization",
                organization_id,
                "custom-cloud-environments",
                byoc_id,
                "permissions",
            ),
            body={"accounts": accounts, "projects": projects},
        )

    def list_byoc_tags(self, organization_id: str, byoc_id: str) -> Mapping:
        output = self.byoc_update(
            organization_id=organization_id,
            byoc_id=byoc_id,
            # Putting all arguments to `None` makes `byoc_update()` behave like a `GET BYOC BY ID` API which does not exist.
            deployment_model=None,
            cloud_provider=None,
            cloud_region=None,
            reserved_cidr=None,
            display_name=None,
            tags=None,
        )
        return {"tags": output.get("custom_cloud_environment", {}).get("tags", {})}

    def update_byoc_tags(self, organization_id: str, byoc_id: str, tag_updates: Mapping[str, str | None]) -> Mapping:
        self.byoc_update(
            organization_id=organization_id,
            byoc_id=byoc_id,
            deployment_model=None,
            cloud_provider=None,
            cloud_region=None,
            reserved_cidr=None,
            display_name=None,
            tags=tag_updates,
        )
        # There have been no errors raised
        return {"message": "tags updated"}

    def replace_byoc_tags(self, organization_id: str, byoc_id: str, tags: Mapping[str, str]) -> Mapping:
        self.byoc_update(
            organization_id=organization_id,
            byoc_id=byoc_id,
            deployment_model=None,
            cloud_provider=None,
            cloud_region=None,
            reserved_cidr=None,
            display_name=None,
            tags=tags,
        )
        # There have been no errors raised
        return {"message": "tags updated"}

    def alloydbomni_google_cloud_private_key_set(self, *, project: str, service: str, private_key: str) -> dict[str, Any]:
        return self.verify(
            self.post,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "alloydbomni",
                "google_cloud_private_key",
            ),
            body={"private_key": private_key},
        )

    def alloydbomni_google_cloud_private_key_delete(self, *, project: str, service: str) -> dict[str, Any]:
        return self.verify(
            self.delete,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "alloydbomni",
                "google_cloud_private_key",
            ),
        )

    def alloydbomni_google_cloud_private_key_show(self, *, project: str, service: str) -> dict[str, Any]:
        return self.verify(
            self.get,
            self.build_path(
                "project",
                project,
                "service",
                service,
                "alloydbomni",
                "google_cloud_private_key",
            ),
        )

    def service_kafka_native_acl_add(
        self,
        project: str,
        service: str,
        principal: str,
        host: str,
        resource_name: str,
        resource_type: str,
        resource_pattern_type: str,
        operation: str,
        permission_type: str,
    ) -> Mapping:
        return self.verify(
            self.post,
            self.build_path("project", project, "service", service, "kafka", "acl"),
            body={
                "principal": principal,
                "host": host,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "pattern_type": resource_pattern_type,
                "operation": operation,
                "permission_type": permission_type,
            },
        )

    def service_kafka_native_acl_list(
        self,
        project: str,
        service: str,
    ) -> dict[str, Any]:
        return self.verify(
            self.get,
            self.build_path("project", project, "service", service, "kafka", "acl"),
        )

    def service_kafka_native_acl_delete(self, project: str, service: str, acl_id: str) -> Mapping:
        return self.verify(
            self.delete,
            self.build_path("project", project, "service", service, "kafka", "acl", acl_id),
        )
