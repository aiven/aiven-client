# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

try:
    from .version import __version__  # pylint: disable=no-name-in-module
except ImportError:
    __version__ = "UNKNOWN"

import json
import logging
import os
import requests


class Error(Exception):
    """Request error"""
    def __init__(self, response, status=520):
        Exception.__init__(self, response.text)
        self.response = response
        self.status = status


class AivenClientBase(object):
    """Aiven Client with low-level HTTP operations"""
    def __init__(self, base_url, show_http=False):
        self.log = logging.getLogger("AivenClient")
        self.auth_token = None
        self.base_url = base_url
        self.log.debug("using %r", self.base_url)
        self.session = requests.Session()
        self.session.verify = "/etc/pki/tls/certs/ca-bundle.crt"
        self.session.headers = {
            "content-type": "application/json",
            "user-agent": "aiven-client/" + __version__,
        }
        self.http_log = logging.getLogger("aiven_http")
        self.init_http_logging(show_http)
        self.api_prefix = "/v1beta"

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

    def verify(self, op, path, body=None, params=None, result_key=None):
        path = self.api_prefix + path
        if body:
            response = op(path=path, body=body, params=params)
        else:
            response = op(path=path, params=params)

        result = response.json()
        if result.get("error"):
            raise Error("server returned error: {op} {base_url}{path} {result}".format(
                op=op.__doc__, base_url=self.base_url, path=path, result=result))
        if result_key is not None:
            return result[result_key]
        else:
            return result


class AivenClient(AivenClientBase):
    """Aiven Client with high-level operations"""
    def get_clouds(self, project):
        return self.verify(self.get, "/project/{}/clouds".format(project), result_key="clouds")

    def get_service(self, project, service_name):
        return self.verify(self.get, "/project/{}/service/{}".format(project, service_name),
                           result_key="service")

    def authenticate_user(self, email, password):
        return self.verify(self.post, "/userauth", body={
            "email": email,
            "password": password,
        })

    def create_service(self, project, service, service_type, group_name, plan,
                       cloud=None, user_config=None):
        user_config = user_config or {}
        return self.verify(self.post, "/project/{}/service".format(project), body={
            "group_name": group_name,
            "cloud": cloud,
            "plan": plan,
            "service_name": service,
            "service_type": service_type,
            "user_config": user_config,
        }, result_key="service")

    def update_service(self,
                       project,
                       service,
                       group_name=None,
                       cloud=None,
                       user_config=None,
                       plan=None,
                       powered=None):
        user_config = user_config or {}
        return self.verify(self.put, "/project/{}/service/{}".format(project, service), body={
            "group_name": group_name,
            "cloud": cloud,
            "plan": plan,
            "powered": powered,
            "user_config": user_config,
        }, result_key="service")

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
        return self.verify(self.get, "/project/{}/service_types".format(project), result_key="service_types")

    def create_project(self, project, card_id=None, cloud=None):
        return self.verify(self.post, "/project", body={
            "project": project,
            "card_id": card_id,
            "cloud": cloud,
        }, result_key="project")

    def delete_project(self, project):
        return self.verify(self.delete, "/project/{}".format(project))

    def get_project(self, project):
        return self.verify(self.get, "/project/{}".format(project), result_key="project")

    def get_projects(self):
        return self.verify(self.get, "/project", result_key="projects")

    def update_project(self, project, card_id=None, cloud=None):
        return self.verify(self.put, "/project/{}".format(project), body={
            "card_id": card_id,
            "cloud": cloud,
        }, result_key="project")

    def invite_project_user(self, project, user_email):
        return self.verify(self.post, "/project/{}/user/invite".format(project), body={
            "user_email": user_email,
        })

    def remove_project_user(self, project, user_email):
        return self.verify(self.put, "/project/{}/user/remove".format(project), body={
            "user_email": user_email,
        })

    def list_project_users(self, project):
        return self.verify(self.get, "/project/{}/user/list".format(project), body={},
                           result_key="users")

    def create_user(self, email, password, real_name):
        request = {
            "email": email,
            "real_name": real_name,
        }
        if password is not None:
            request["password"] = password
        return self.verify(self.post, "/user", body=request)

    def get_logs(self, project, limit=100, offset=None):
        params = {"limit": limit}
        if offset:
            params["offset"] = offset
        return self.verify(self.get, "/project/{}/logs".format(project), params=params)

    def list_data(self, project):
        return self.verify(self.get, "/project/{}/data".format(project))

    def download_data(self, project, filename):
        path = self.api_prefix + "/project/{}/data/{}".format(project, os.path.basename(filename))
        return self.get(path).content

    def upload_data(self, project, filename):
        with open(filename, "rb") as fp:
            path = "/project/{}/data/{}".format(project, os.path.basename(filename))
            return self.verify(self.put, path, body=fp)

    def delete_data(self, project, filename):
        path = "/project/{}/data/{}".format(project, os.path.basename(filename))
        return self.verify(self.delete, path)

    def get_cards(self):
        return self.verify(self.get, "/card", result_key="cards")

    def add_card(self, stripe_token):
        request = {
            "stripe_token": stripe_token,
        }
        return self.verify(self.post, "/card", body=request, result_key="card")

    def update_card(self, card_id, **kwargs):
        keys = {"address_city", "address_country", "address_line1",
                "address_line2", "address_state", "address_zip",
                "exp_month", "exp_year", "name"}
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

    def list_credits(self):
        return self.verify(self.get, "/credits", result_key="credits")

    def claim_credit(self, credit_code):
        return self.verify(self.post, "/credits", body={"code": credit_code}, result_key="credit")
