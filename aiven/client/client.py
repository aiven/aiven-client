# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
import warnings

try:
    from .version import __version__  # pylint: disable=no-name-in-module
except ImportError:
    __version__ = "UNKNOWN"

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

import json
import logging
import requests
import time


class Error(Exception):
    """Request error"""
    def __init__(self, response, status=520):
        Exception.__init__(self, response.text)
        self.response = response
        self.status = status


UNDEFINED = object()


class AivenClientBase:  # pylint: disable=old-style-class
    """Aiven Client with low-level HTTP operations"""
    def __init__(self, base_url, show_http=False):
        self.log = logging.getLogger("AivenClient")
        self.auth_token = None
        self.base_url = base_url
        self.log.debug("using %r", self.base_url)
        self.session = requests.Session()
        self.session.verify = True
        self.session.headers = {
            "content-type": "application/json",
            "user-agent": "aiven-client/" + __version__,
        }
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
                self.log.warning("%s %s failed: %s: %s; retrying in 0.2 seconds, %s attempts left",
                                 op.__name__.upper(), path, ex.__class__.__name__, ex, attempts)
                time.sleep(0.2)

        result = response.json()
        if result.get("error"):
            raise Error("server returned error: {op} {base_url}{path} {result}".format(
                op=op.__doc__, base_url=self.base_url, path=path, result=result))

        if result_key is not None:
            return result[result_key]
        return result


class AivenClient(AivenClientBase):
    """Aiven Client with high-level operations"""

    def get_service_indexes(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}/index".format(project, service),
                           result_key="indexes")

    def delete_service_index(self, project, service, index_name):
        return self.verify(self.delete, "/project/{}/service/{}/index/{}".format(project, service, index_name))

    def get_clouds(self, project):
        if project is None:
            path = "/clouds"
        else:
            path = "/project/{}/clouds".format(project)
        return self.verify(self.get, path, result_key="clouds")

    def get_service(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}".format(project, service),
                           result_key="service")

    def get_service_metrics(self, project, service, period):
        return self.verify(
            self.post, "/project/{}/service/{}/metrics".format(project, service),
            result_key="metrics", body={
                "period": period
            })

    def authenticate_user(self, email, password, otp=None):
        body = {
            "email": email,
            "password": password,
        }
        if otp is not None:
            body["otp"] = otp

        return self.verify(self.post, "/userauth", body=body)

    def create_service_connection_pool(self, project, service, pool_name, dbname, username, pool_size=None, pool_mode=None):
        body = {"database": dbname, "username": username, "pool_name": pool_name}
        if pool_size:
            body["pool_size"] = pool_size
        if pool_mode:
            body["pool_mode"] = pool_mode
        return self.verify(self.post, "/project/{}/service/{}/connection_pool".format(project, service), body=body)

    def update_service_connection_pool(self, project, service, pool_name,
                                       dbname=None, username=None, pool_size=None, pool_mode=None):
        body = {}
        if username is not None:
            body["username"] = username
        if dbname is not None:
            body["database"] = dbname
        if pool_size is not None:
            body["pool_size"] = pool_size
        if pool_mode is not None:
            body["pool_mode"] = pool_mode
        return self.verify(self.put, "/project/{}/service/{}/connection_pool/{}".format(
            project, service, pool_name), body=body)

    def delete_service_connection_pool(self, project, service, pool_name):
        return self.verify(self.delete, "/project/{}/service/{}/connection_pool/{}".format(project, service, pool_name))

    def create_service_database(self, project, service, dbname):
        return self.verify(self.post, "/project/{}/service/{}/db".format(project, service),
                           body={"database": dbname})

    def delete_service_database(self, project, service, dbname):
        return self.verify(self.delete, "/project/{}/service/{}/db/{}".format(project, service, dbname))

    def create_service_user(self, project, service, username):
        return self.verify(self.post, "/project/{}/service/{}/user".format(project, service), body={
            "username": username,
        }, result_key="user")

    def delete_service_user(self, project, service, username):
        return self.verify(self.delete, "/project/{}/service/{}/user/{}".format(project, service, username))

    def reset_service_user_password(self, project, service, username):
        return self.verify(self.put, "/project/{}/service/{}/user/{}/credentials/reset".format(project, service, username))

    def get_service_integration_endpoints(self, project):
        return self.verify(self.get, "/project/{}/integration_endpoint".format(project),
                           result_key="service_integration_endpoints")

    def get_service_integration_endpoint_types(self, project):
        return self.verify(self.get, "/project/{}/integration_endpoint_types".format(project),
                           result_key="endpoint_types")

    def create_service_integration_endpoint(self, project, endpoint_name, endpoint_type, user_config):
        return self.verify(self.post, "/project/{}/integration_endpoint".format(project), body={
            "endpoint_name": endpoint_name,
            "endpoint_type": endpoint_type,
            "user_config": user_config,
        })

    def update_service_integration_endpoint(self, project, endpoint_id, user_config):
        return self.verify(self.put, "/project/{}/integration_endpoint/{}".format(
            project, endpoint_id),
                           body={
                               "user_config": user_config,
                           })

    def delete_service_integration_endpoint(self, project, endpoint_id):
        return self.verify(self.delete, "/project/{}/integration_endpoint/{}".format(project, endpoint_id))

    def get_service_integrations(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}/integration".format(project, service),
                           result_key="service_integrations")

    def get_service_integration_types(self, project):
        return self.verify(self.get, "/project/{}/integration_types".format(project),
                           result_key="integration_types")

    def create_service_integration(self, project, integration_type,
                                   source_service=None, dest_service=None,
                                   source_endpoint_id=None, dest_endpoint_id=None,
                                   user_config=None):
        user_config = user_config or {}
        return self.verify(self.post, "/project/{}/integration".format(project), body={
            "source_endpoint_id": source_endpoint_id,
            "source_service": source_service,
            "dest_endpoint_id": dest_endpoint_id,
            "dest_service": dest_service,
            "integration_type": integration_type,
            "user_config": user_config,
        })

    def update_service_integration(self, project, integration_id, user_config):
        return self.verify(self.put, "/project/{}/integration/{}".format(project, integration_id), body={
            "user_config": user_config,
        }, result_key="service_integration")

    def get_service_integration(self, project, integration_id):
        return self.verify(self.get, "/project/{}/integration/{}".format(project, integration_id),
                           result_key="service_integration")

    def delete_service_integration(self, project, integration_id):
        return self.verify(self.delete, "/project/{}/integration/{}".format(project, integration_id))

    def create_service_task(self, project, service, operation, target_version):
        return self.verify(self.post, "/project/{}/service/{}/task".format(project, service), body={
            "task_type": operation,
            "target_version": target_version,
        })

    def get_service_task(self, project, service, task_id):
        return self.verify(self.get, "/project/{}/service/{}/task/{}".format(project, service, task_id),
                           result_key="task")

    def get_service_topic(self, project, service, topic):
        return self.verify(self.get, "/project/{}/service/{}/topic/{}".format(project, service, topic),
                           result_key="topic")

    def list_service_topics(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}/topic".format(project, service), result_key="topics")

    def create_service_topic(self, project, service, topic, partitions, replication,
                             min_insync_replicas, retention_bytes, retention_hours,
                             cleanup_policy):
        return self.verify(self.post, "/project/{}/service/{}/topic".format(project, service), body={
            "cleanup_policy": cleanup_policy,
            "min_insync_replicas": min_insync_replicas,
            "topic_name": topic,
            "partitions": partitions,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        })

    def update_service_topic(self, project, service, topic, partitions, retention_bytes,
                             retention_hours, min_insync_replicas, replication=None):
        return self.verify(self.put, "/project/{}/service/{}/topic/{}".format(project, service, topic), body={
            "partitions": partitions,
            "min_insync_replicas": min_insync_replicas,
            "replication": replication,
            "retention_bytes": retention_bytes,
            "retention_hours": retention_hours,
        })

    def delete_service_topic(self, project, service, topic):
        return self.verify(self.delete, "/project/{}/service/{}/topic/{}".format(project, service, topic))

    def add_service_kafka_acl(self, project, service, permission, topic, username):
        return self.verify(self.post, "/project/{}/service/{}/acl".format(project, service), body={
            "permission": permission,
            "topic": topic,
            "username": username,
        })

    def delete_service_kafka_acl(self, project, service, acl_id):
        return self.verify(self.delete, "/project/{}/service/{}/acl/{}".format(project, service, acl_id))

    def get_available_kafka_connectors(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}/available-connectors".format(project, service))

    def list_kafka_connectors(self, project, service):
        return self.verify(self.get, "/project/{}/service/{}/connectors".format(project, service))

    def get_kafka_connector_status(self, project, service, connector_name):
        return self.verify(self.get, "/project/{}/service/{}/connectors/{}/status".format(project, service, connector_name))

    def get_kafka_connector_configuration(self, project, service, connector_name):
        url = "/project/{}/service/{}/connector-plugins/{}/configuration"
        return self.verify(self.get, url.format(project, service, connector_name))

    def create_kafka_connector(self, project, service, config):
        return self.verify(self.post, "/project/{}/service/{}/connectors".format(project, service), body=config)

    def update_kafka_connector(self, project, service, connector_name, config):
        url = "/project/{}/service/{}/connectors/{}"
        return self.verify(self.put, url.format(project, service, connector_name), body=config)

    def delete_kafka_connector(self, project, service, connector_name):
        return self.verify(self.delete, "/project/{}/service/{}/connectors/{}".format(project, service, connector_name))

    def pause_kafka_connector(self, project, service, connector_name):
        return self.verify(self.post, "/project/{}/service/{}/connectors/{}/pause".format(project, service, connector_name))

    def resume_kafka_connector(self, project, service, connector_name):
        return self.verify(self.post, "/project/{}/service/{}/connectors/{}/resume".format(project, service, connector_name))

    def restart_kafka_connector(self, project, service, connector_name):
        url = "/project/{}/service/{}/connectors/{}/restart"
        return self.verify(self.post, url.format(project, service, connector_name))

    def restart_kafka_connector_task(self, project, service, connector_name, task_id):
        url = "/project/{}/service/{}/connectors/{}/tasks/{}/restart"
        return self.verify(self.post, url.format(project, service, connector_name, task_id))

    def list_project_vpcs(self, project):
        return self.verify(self.get, "/project/{}/vpcs".format(project))

    def create_project_vpc(self, project, cloud, network_cidr, peering_connections):
        return self.verify(self.post, "/project/{}/vpcs".format(project), body={
            "cloud_name": cloud,
            "network_cidr": network_cidr,
            "peering_connections": peering_connections,
        })

    def request_project_vpc(self, project, cloud, network_cidr, peering_connections):
        warnings.warn("Use the create_project_vpc method", DeprecationWarning)
        return self.create_project_vpc(
            project=project,
            cloud=cloud,
            network_cidr=network_cidr,
            peering_connections=peering_connections,
        )

    def get_project_vpc(self, project, project_vpc_id):
        return self.verify(self.get, "/project/{}/vpcs/{}".format(project, project_vpc_id))

    def delete_project_vpc(self, project, project_vpc_id):
        return self.verify(self.delete, "/project/{}/vpcs/{}".format(project, project_vpc_id))

    def create_project_vpc_peering_connection(self, project, project_vpc_id, peer_cloud_account, peer_vpc, peer_region=None):
        return self.verify(self.post, "/project/{}/vpcs/{}/peering-connections".format(project, project_vpc_id), body={
            "peer_cloud_account": peer_cloud_account,
            "peer_vpc": peer_vpc,
            "peer_region": peer_region,
        })

    def request_project_vpc_peering_connection(self, project, project_vpc_id, peer_cloud_account, peer_vpc):
        warnings.warn("Use the create_project_vpc_peering_connection method", DeprecationWarning)
        return self.create_project_vpc_peering_connection(
            project=project,
            project_vpc_id=project_vpc_id,
            peer_cloud_account=peer_cloud_account,
            peer_vpc=peer_vpc,
        )

    def delete_project_vpc_peering_connection(self, project, project_vpc_id, peer_cloud_account, peer_vpc, peer_region=None):
        url = "/project/{}/vpcs/{}/peering-connections/peer-accounts/{}/peer-vpcs/{}".format(
            project, project_vpc_id, peer_cloud_account, peer_vpc,
        )
        if peer_region is not None:
            url += "/peer-regions/{}".format(peer_region)
        return self.verify(self.delete, url)

    def create_service(self, project, service, service_type, group_name, plan,
                       cloud=None, user_config=None, project_vpc_id=UNDEFINED, service_integrations=None):
        user_config = user_config or {}
        body = {
            "group_name": group_name,
            "cloud": cloud,
            "plan": plan,
            "service_integrations": service_integrations,
            "service_name": service,
            "service_type": service_type,
            "user_config": user_config,
        }
        if project_vpc_id is not UNDEFINED:
            body["project_vpc_id"] = project_vpc_id
        return self.verify(self.post, "/project/{}/service".format(project), body=body, result_key="service")

    def update_service(self,
                       project,
                       service,
                       group_name=None,
                       cloud=None,
                       maintenance=None,
                       user_config=None,
                       plan=None,
                       powered=None,
                       project_vpc_id=UNDEFINED):
        user_config = user_config or {}
        body = {}
        if group_name is not None:
            body["group_name"] = group_name
        if cloud is not None:
            body["cloud"] = cloud
        if maintenance is not None:
            body["maintenance"] = maintenance
        if plan is not None:
            body["plan"] = plan
        if powered is not None:
            body["powered"] = powered
        if user_config is not None:
            body["user_config"] = user_config
        if project_vpc_id is not UNDEFINED:
            body["project_vpc_id"] = project_vpc_id

        return self.verify(self.put, "/project/{}/service/{}".format(project, service), body=body, result_key="service")

    def reset_service_credentials(self, project, service):
        return self.verify(self.put, "/project/{}/service/{}/credentials/reset".format(project, service),
                           result_key="service")

    def delete_service(self, project, service):
        return self.verify(self.delete, "/project/{}/service/{}".format(project, service))

    def get_pg_service_current_queries(self, project, service):
        return self.verify(self.post, "/project/{}/service/{}/query/activity".format(project, service),
                           result_key="queries", body={"limit": 100, "order_by": "query_duration:desc"})

    def get_pg_service_query_stats(self, project, service):
        return self.verify(self.post, "/project/{}/service/{}/query/stats".format(project, service),
                           result_key="queries", body={"limit": 100, "order_by": "calls:desc"})

    def reset_pg_service_query_stats(self, project, service):
        return self.verify(self.put, "/project/{}/service/{}/query/stats/reset".format(project, service),
                           result_key="queries")

    def get_services(self, project):
        return self.verify(self.get, "/project/{}/service".format(project), result_key="services")

    def get_service_types(self, project):
        if project is None:
            path = "/service_types"
        else:
            path = "/project/{}/service_types".format(project)
        return self.verify(self.get, path, result_key="service_types")

    def create_project(
            self,
            project,
            card_id=None,
            cloud=None,
            copy_from_project=None,
            country_code=None,
            billing_address=None,
            billing_currency=None,
            billing_extra_text=None,
            vat_id=None
    ):
        body = {
            "card_id": card_id,
            "cloud": cloud,
            "project": project,
        }
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

        return self.verify(self.post, "/project", body=body, result_key="project")

    def delete_project(self, project):
        return self.verify(self.delete, "/project/{}".format(project))

    def get_project(self, project):
        return self.verify(self.get, "/project/{}".format(project), result_key="project")

    def get_projects(self):
        return self.verify(self.get, "/project", result_key="projects")

    def update_project(
            self,
            project,
            card_id=None,
            cloud=None,
            country_code=None,
            billing_address=None,
            billing_currency=None,
            billing_extra_text=None,
            vat_id=None
    ):
        body = {}
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

        return self.verify(self.put, "/project/{}".format(project), body=body, result_key="project")

    def get_project_ca(self, project):
        return self.verify(self.get, "/project/{}/kms/ca".format(project))

    def invite_project_user(self, project, user_email, member_type=None):
        body = {
            "user_email": user_email,
        }
        if member_type is not None:
            body["member_type"] = member_type
        return self.verify(self.post, "/project/{}/invite".format(project), body=body)

    def remove_project_user(self, project, user_email):
        return self.verify(self.delete, "/project/{}/user/{}".format(project, user_email))

    def list_project_users(self, project):
        return self.verify(self.get, "/project/{}/users".format(project), result_key="users")

    def create_user(self, email, password, real_name):
        request = {
            "email": email,
            "real_name": real_name,
        }
        if password is not None:
            request["password"] = password
        return self.verify(self.post, "/user", body=request)

    def get_user_info(self):
        return self.verify(self.get, "/me", result_key="user")

    def access_token_create(self, description, extend_when_used=False, max_age_seconds=None):
        request = {
            "description": description,
            "extend_when_used": extend_when_used,
            "max_age_seconds": max_age_seconds
        }
        return self.verify(self.post, "/access_token", body=request)

    def access_token_revoke(self, token_prefix):
        if any(c in token_prefix for c in "/+="):
            token_prefix = quote(token_prefix, safe="")
        return self.verify(self.delete, "/access_token/{}".format(token_prefix))

    def access_token_update(self, token_prefix, description):
        if any(c in token_prefix for c in "/+="):
            token_prefix = quote(token_prefix, safe="")
        request = {
            "description": description
        }
        return self.verify(self.put, "/access_token/{}".format(token_prefix), body=request)

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
        return self.verify(self.post, "/project/{}/service/{}/logs".format(project, service), body=body)

    def get_events(self, project, limit=100):
        params = {"limit": limit}
        return self.verify(self.get, "/project/{}/events".format(project), params=params,
                           result_key="events")

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

        return self.verify(self.put, "/card/{}".format(card_id), body=request, result_key="card")

    def remove_card(self, card_id):
        return self.verify(self.delete, "/card/{}".format(card_id))

    def get_stripe_key(self):
        return self.verify(self.get, "/config/stripe_key")

    def list_project_credits(self, project):
        return self.verify(self.get, "/project/{}/credits".format(project), result_key="credits")

    def claim_project_credit(self, project, credit_code):
        return self.verify(self.post, "/project/{}/credits".format(project), body={"code": credit_code}, result_key="credit")

    def start_service_maintenance(self, project, service):
        return self.verify(self.put, "/project/{}/service/{}/maintenance/start".format(project, service))
