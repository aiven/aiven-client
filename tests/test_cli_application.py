# Copyright 2026, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""Aiven Runtime application commands, exercised through a real AivenClient over a fake HTTP session."""

from __future__ import annotations

from aiven.client import AivenClient
from aiven.client.cli import AivenCLI
from aiven.client.client import RetrySpec
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from pytest import CaptureFixture, LogCaptureFixture
from tests.test_client import MockResponse
from typing import Any

import json
import logging
import pytest

BASE_URL = "https://api.example.invalid"
PROJECT = "test-project"
APP = "example-app"
SERVICE_PATH = f"/project/{PROJECT}/service/{APP}"
VCS_PATH = "/organization/org123/application/vcs-integrations"
SHA = "0123456789abcdef0123456789abcdef01234567"

APPLICATION_USER_CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "application": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "object",
                    "properties": {
                        "repository_url": {"type": "string"},
                        "branch": {"type": "string"},
                        "build_path": {"type": "string"},
                        "containerfile_path": {"type": ["string", "null"]},
                        "vcs_integration_id": {"type": "string"},
                        "remote_repository_id": {"type": "string"},
                    },
                },
                "ports": {"type": "array", "items": {"type": "object"}},
                "environment_variables": {"type": "array", "items": {"type": "object"}},
            },
        },
    },
}


@dataclass
class RecordedRequest:
    method: str
    path: str
    params: dict[str, Any] | None
    body: Any


@dataclass
class FakeSession:
    """Stands in for requests.Session: answers by (method, path) and records every request."""

    routes: dict[tuple[str, str], MockResponse]
    requests: list[RecordedRequest] = field(default_factory=list)

    def _handle(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        path = url.removeprefix(BASE_URL + "/v1")
        data = kwargs.get("data")
        self.requests.append(
            RecordedRequest(method=method, path=path, params=kwargs.get("params"), body=json.loads(data) if data else None)
        )
        response = self.routes.get((method, path))
        if response is None:
            return MockResponse(HTTPStatus.NOT_FOUND, {"message": f"no fake route for {method} {path}"})
        return response

    def get(self, url: str, **kwargs: Any) -> MockResponse:
        return self._handle("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> MockResponse:
        return self._handle("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> MockResponse:
        return self._handle("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> MockResponse:
        return self._handle("DELETE", url, **kwargs)

    def paths(self, method: str) -> list[str]:
        return [request.path for request in self.requests if request.method == method]


@dataclass
class CLIRunner:
    session: FakeSession
    config_path: Path

    def run(self, *args: str) -> int | None:
        def client_factory(**kwargs: Any) -> AivenClient:
            # No retries: a failing request fails the test at once instead of sleeping between attempts.
            client = AivenClient(**kwargs, default_retry_spec=RetrySpec(attempts=1))
            client.session = self.session  # type: ignore[assignment]
            return client

        return AivenCLI(client_factory=client_factory).run(
            args=["--config", str(self.config_path), "--auth-token", "token", "--url", BASE_URL, *args],
        )


def build_cli(tmp_path: Path, routes: dict[tuple[str, str], MockResponse]) -> CLIRunner:
    return CLIRunner(session=FakeSession(routes=routes), config_path=tmp_path / "avn.json")


def ok(body: dict[str, Any]) -> MockResponse:
    return MockResponse(HTTPStatus.OK, body, headers={"content-type": "application/json"})


def app_service(
    state: str,
) -> dict[str, Any]:
    return {
        "service_name": APP,
        "service_type": "application",
        "state": state,
        "plan": "startup-50-1024",
        "user_config": {
            "application": {"source": {"repository_url": "https://github.com/example/app.git", "branch": "main"}}
        },
    }


def service_response(*args: Any, **kwargs: Any) -> MockResponse:
    return ok({"service": app_service(*args, **kwargs)})


def create_routes() -> dict[tuple[str, str], MockResponse]:
    return {
        ("GET", f"/project/{PROJECT}/service-types/application"): ok({"user_config_schema": APPLICATION_USER_CONFIG_SCHEMA}),
        ("GET", f"/project/{PROJECT}/vpcs"): ok({"vpcs": []}),
        ("POST", f"/project/{PROJECT}/service"): ok({"service": app_service("REBUILDING")}),
    }


def test_service_create_documented_config_options(tmp_path: Path) -> None:
    """The CLI example of docs/products/runtime/deploy-apps.md in aiven-docs."""
    cli = build_cli(tmp_path, create_routes())

    assert (
        cli.run(
            *("service", "create", APP, "--project", PROJECT, "-t", "application"),
            *("--cloud", "aws-eu-west-1", "--plan", "startup-50-1024"),
            *("-c", "application.source.vcs_integration_id=vcs123", "-c", "application.source.remote_repository_id=r1"),
            *("-c", "application.source.repository_url=https://github.com/example/app.git"),
            *("-c", "application.source.branch=main", "-c", "application.source.build_path=."),
            *("-c", "application.source.containerfile_path=Dockerfile"),
            *("-c", 'application.ports=[{"name":"http","port":8080,"protocol":"HTTP"}]'),
        )
        is None
    )

    create = cli.session.requests[-1]
    assert (create.method, create.path) == ("POST", f"/project/{PROJECT}/service")
    assert create.body["service_type"] == "application"
    assert create.body["user_config"] == {
        "application": {
            "source": {
                "vcs_integration_id": "vcs123",
                "remote_repository_id": "r1",
                "repository_url": "https://github.com/example/app.git",
                "branch": "main",
                "build_path": ".",
                "containerfile_path": "Dockerfile",
            },
            "ports": [{"name": "http", "port": 8080, "protocol": "HTTP"}],
        }
    }


@pytest.mark.parametrize("from_file", [False, True], ids=["inline", "file"])
def test_service_create_user_config_json(tmp_path: Path, from_file: bool) -> None:
    user_config = {
        "application": {
            "source": {"repository_url": "https://github.com/example/app.git", "branch": "main"},
            "environment_variables": [{"key": "DEBUG", "value": "true", "kind": "variable"}],
        }
    }
    cli = build_cli(tmp_path, create_routes())

    args = ["service", "create", APP, "--project", PROJECT, "-t", "application", "--plan", "startup-50-1024"]
    user_config_json = json.dumps(user_config)
    if from_file:
        config_file = tmp_path / "app.json"
        config_file.write_text(user_config_json, encoding="utf-8")
        user_config_json = f"@{config_file}"
    assert cli.run(*args, "--user-config-json", user_config_json) is None

    assert cli.session.paths("GET") == []
    assert cli.session.requests[-1].body["user_config"] == user_config


@pytest.mark.parametrize(
    ("command", "extra_args", "message"),
    [
        (["create", APP, "-t", "application", "--plan", "p"], ["-c", "application.source.branch=main"], "-c (user config)"),
        (["create", APP, "-t", "application", "--plan", "p"], ["--user-config-json", "[]"], "expected a JSON object"),
        (["create", APP, "-t", "application", "--plan", "p"], ["--user-config-json", "null"], "expected a JSON object"),
        (
            ["create", APP, "-t", "application", "--plan", "p"],
            ["--user-config-json", "@/nonexistent/app.json"],
            "Cannot read",
        ),
        (["update", APP], ["--remove-option", "application.source.containerfile_path"], "--remove-option"),
    ],
)
def test_service_user_config_json_conflicts(
    tmp_path: Path, caplog: LogCaptureFixture, command: list[str], extra_args: list[str], message: str
) -> None:
    user_config_json = [] if "--user-config-json" in extra_args else ["--user-config-json", "{}"]
    cli = build_cli(tmp_path, {("GET", SERVICE_PATH): service_response("RUNNING")})

    assert cli.run("service", *command, "--project", PROJECT, *user_config_json, *extra_args) == 1
    assert message in caplog.text
    assert cli.session.paths("POST") == cli.session.paths("PUT") == []


def test_service_create_user_config_json_file_not_utf8(tmp_path: Path, caplog: LogCaptureFixture) -> None:
    config_file = tmp_path / "app.json"
    config_file.write_bytes(b"\xff\xfe{}")
    cli = build_cli(tmp_path, create_routes())

    args = ["service", "create", APP, "--project", PROJECT, "-t", "application", "--plan", "startup-50-1024"]
    assert cli.run(*args, "--user-config-json", f"@{config_file}") == 1
    assert "Cannot read user_config_json file" in caplog.text


@pytest.mark.parametrize("from_file", [False, True], ids=["inline", "file"])
def test_service_update_user_config_json(tmp_path: Path, from_file: bool) -> None:
    cli = build_cli(
        tmp_path,
        {
            ("GET", SERVICE_PATH): service_response("RUNNING"),
            ("PUT", SERVICE_PATH): ok({"service": app_service("RUNNING")}),
        },
    )

    # null is how --user-config-json removes an option.
    user_config = {"application": {"source": {"branch": "release", "containerfile_path": None}}}
    user_config_json = json.dumps(user_config)
    if from_file:
        config_file = tmp_path / "app.json"
        config_file.write_text(user_config_json, encoding="utf-8")
        user_config_json = f"@{config_file}"
    assert cli.run("service", "update", APP, "--project", PROJECT, "--user-config-json", user_config_json) is None

    assert cli.session.paths("GET") == [SERVICE_PATH]
    assert cli.session.requests[-1].body["user_config"] == user_config


@pytest.mark.parametrize(
    ("extra_args", "expected_log_type"),
    [(["--log-type", "application-build"], "application-build"), ([], None)],
)
def test_service_logs_log_type(tmp_path: Path, extra_args: list[str], expected_log_type: str | None) -> None:
    logs: dict[str, Any] = {"logs": [], "offset": None, "first_log_offset": None}
    cli = build_cli(tmp_path, {("POST", SERVICE_PATH + "/logs"): ok(logs)})

    assert cli.run("service", "logs", "--project", PROJECT, *extra_args, APP) is None
    assert cli.session.requests[0].body.get("log_type") == expected_log_type


VCS_INTEGRATION = {
    "vcs_integration_id": "vcs123",
    "vcs_type": "github",
    "vcs_account_name": "example",
    "create_time": "2026-09-01T00:00:00Z",
    "remote_configure_url": None,
}
REPOSITORY = {
    "remote_repository_id": "r1",
    "vcs_integration_id": "vcs123",
    "vcs_type": "github",
    "full_name": "example/app",
    "name": "app",
    "source_url": "https://github.com/example/app.git",
    "default_branch_name": "main",
}
MANIFEST_ARGS = ["--vcs-integration-id", "vcs123", "--remote-repository-id", "r1", "--commit-sha", SHA]
MANIFEST_FILE = {"file_path": "Dockerfile", "file_sha": "f1", "container_manifest_type": "containerfile"}


@pytest.mark.parametrize(
    ("command", "route", "response", "header"),
    [
        (
            ["vcs-integration", "list"],
            ("GET", VCS_PATH),
            {"vcs_integrations": [VCS_INTEGRATION]},
            ["VCS_INTEGRATION_ID", "VCS_TYPE", "VCS_ACCOUNT_NAME", "CREATE_TIME"],
        ),
        (
            ["repository", "list", "--vcs-integration-id", "vcs123"],
            ("GET", VCS_PATH + "/vcs123/repositories"),
            {"repositories": [REPOSITORY], "next": None, "previous": None},
            ["REMOTE_REPOSITORY_ID", "FULL_NAME", "SOURCE_URL", "DEFAULT_BRANCH_NAME"],
        ),
        (
            ["branch", "list", "--vcs-integration-id", "vcs123", "--remote-repository-id", "r1"],
            ("GET", VCS_PATH + "/vcs123/repositories/r1/branches"),
            {"branches": [{"name": "main", "commit_sha": SHA}], "next": None, "previous": None},
            ["NAME", "COMMIT_SHA"],
        ),
        (
            ["container-manifest", "list", *MANIFEST_ARGS],
            ("GET", VCS_PATH + f"/vcs123/repositories/r1/refs/{SHA}/container-manifest-files"),
            {"container_manifest_files": [MANIFEST_FILE]},
            ["FILE_PATH", "CONTAINER_MANIFEST_TYPE", "FILE_SHA"],
        ),
        (
            [
                "container-manifest",
                "scan",
                *MANIFEST_ARGS,
                "--branch",
                "main",
                "--repository-url",
                "u",
                "--file-path",
                "Dockerfile",
            ],
            ("POST", VCS_PATH + f"/vcs123/repositories/r1/refs/{SHA}/scan-container-manifest"),
            {"file_scan": {"service_suggestions": [{"service_name": "app", "service_type": "application"}]}},
            ["SERVICE_NAME", "SERVICE_TYPE"],
        ),
    ],
)
def test_service_application_list_tables(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    command: list[str],
    route: tuple[str, str],
    response: dict[str, Any],
    header: list[str],
) -> None:
    cli = build_cli(tmp_path, {route: ok(response)})

    assert cli.run("service", "application", *command, "--organization-id", "org123") is None
    header_line, _separator, *rows = capsys.readouterr().out.splitlines()
    assert header_line.split() == header
    assert len(rows) == 1


def test_service_application_vcs_integration_list_json(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    cli = build_cli(tmp_path, {("GET", VCS_PATH): ok({"vcs_integrations": [VCS_INTEGRATION]})})

    args = ["vcs-integration", "list", "--organization-id", "org123", "--json"]
    assert cli.run("service", "application", *args) is None
    assert json.loads(capsys.readouterr().out) == [VCS_INTEGRATION]


def test_service_application_repository_list_passes_search(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    page = {"repositories": [REPOSITORY], "next": "c2", "previous": None}
    cli = build_cli(tmp_path, {("GET", VCS_PATH + "/vcs123/repositories"): ok(page)})

    args = ["--organization-id", "org123", "--vcs-integration-id", "vcs123", "--search", "app", "--json"]
    assert cli.run("service", "application", "repository", "list", *args) is None

    assert cli.session.requests[0].params == {"search": "app"}
    assert json.loads(capsys.readouterr().out) == page


def test_service_application_repository_list_logs_next_cursor(
    tmp_path: Path, capsys: CaptureFixture[str], caplog: LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    page = {"repositories": [REPOSITORY], "next": "c2", "previous": None}
    cli = build_cli(tmp_path, {("GET", VCS_PATH + "/vcs123/repositories"): ok(page)})

    args = ["--organization-id", "org123", "--vcs-integration-id", "vcs123", "--cursor", "c1"]
    assert cli.run("service", "application", "repository", "list", *args) is None

    assert cli.session.requests[0].params == {"cursor": "c1"}
    assert "example/app" in capsys.readouterr().out
    assert "--cursor c2" in caplog.text


def test_service_application_branch_list_passes_cursor(
    tmp_path: Path, capsys: CaptureFixture[str], caplog: LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    page = {"branches": [{"name": "main", "commit_sha": SHA}], "next": "c2", "previous": None}
    cli = build_cli(tmp_path, {("GET", VCS_PATH + "/vcs123/repositories/r1/branches"): ok(page)})

    args = [
        *("--organization-id", "org123", "--vcs-integration-id", "vcs123", "--remote-repository-id", "r1"),
        *("--cursor", "c1"),
    ]
    assert cli.run("service", "application", "branch", "list", *args) is None

    assert cli.session.requests[0].params == {"cursor": "c1"}
    assert SHA in capsys.readouterr().out
    assert "--cursor c2" in caplog.text


def test_service_application_branch_list_json_keeps_cursors(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    page = {"branches": [{"name": "main", "commit_sha": SHA}], "next": "c2", "previous": "c0"}
    cli = build_cli(tmp_path, {("GET", VCS_PATH + "/vcs123/repositories/r1/branches"): ok(page)})

    args = ["--organization-id", "org123", "--vcs-integration-id", "vcs123", "--remote-repository-id", "r1", "--json"]
    assert cli.run("service", "application", "branch", "list", *args) is None

    assert json.loads(capsys.readouterr().out) == page


def test_service_application_container_manifest_list_json(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    path = VCS_PATH + f"/vcs123/repositories/r1/refs/{SHA}/container-manifest-files"
    cli = build_cli(tmp_path, {("GET", path): ok({"container_manifest_files": [MANIFEST_FILE]})})

    args = ["--organization-id", "org123", *MANIFEST_ARGS, "--json"]
    assert cli.run("service", "application", "container-manifest", "list", *args) is None
    assert json.loads(capsys.readouterr().out) == [MANIFEST_FILE]


def test_service_application_container_manifest_scan_sends_file_and_prints_suggestions(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    file_scan = {"container_manifest_type": "containerfile", "service_suggestions": [{"service_name": "app"}]}
    path = VCS_PATH + f"/vcs123/repositories/r1/refs/{SHA}/scan-container-manifest"
    cli = build_cli(tmp_path, {("POST", path): ok({"file_scan": file_scan})})

    args = [
        *("--organization-id", "org123", *MANIFEST_ARGS),
        *("--branch", "main", "--repository-url", "https://github.com/example/app.git"),
        *("--file-path", "Dockerfile", "--json"),
    ]
    assert cli.run("service", "application", "container-manifest", "scan", *args) is None

    assert cli.session.requests[0].body == {
        "branch": "main",
        "file_path": "Dockerfile",
        "repository_url": "https://github.com/example/app.git",
    }
    assert json.loads(capsys.readouterr().out) == file_scan
