# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client import AivenClient, argx
from aiven.client.argx import UserError
from aiven.client.cli import AivenCLI, ClientFactory, convert_str_to_value, EOL_ADVANCE_WARNING_TIME
from aiven.client.common import UNDEFINED
from argparse import Namespace
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pytest import CaptureFixture, LogCaptureFixture
from requests import Session
from typing import Any, cast, Iterator, Mapping
from unittest import mock
from unittest.mock import ANY, MagicMock

import json
import pytest
import random
import string
import tempfile
import uuid

EXIT_CODE_INVALID_USAGE = 2


def test_cli() -> None:
    with pytest.raises(SystemExit) as excinfo:
        AivenCLI().run(args=["--help"])
    assert excinfo.value.code == 0


def test_cloud_list() -> None:
    AivenCLI().run(args=["cloud", "list"])


def test_service_plans() -> None:
    AivenCLI().run(args=["service", "plans"])


def test_service_types_v() -> None:
    AivenCLI().run(args=["service", "types", "-v"])


def test_service_user_create() -> None:
    AivenCLI().run(args=["service", "user-create", "service", "--username", "username"])


@pytest.mark.parametrize(
    "command_line, expected_post_data",
    [
        (
            "service topic-create --project project1 --partitions 42 --replication 4 service1 topic1",
            {
                "topic_name": "topic1",
                "partitions": 42,
                "replication": 4,
                "cleanup_policy": "delete",
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "tags": [],
            },
        ),
        (
            (
                "service topic-create --project project1 --partitions 42 --replication 4 "
                + "--tag key-_1=value1 --tag key2=az,.0-9_ service1 topic1"
            ),
            {
                "topic_name": "topic1",
                "partitions": 42,
                "replication": 4,
                "cleanup_policy": "delete",
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "tags": [{"key": "key-_1", "value": "value1"}, {"key": "key2", "value": "az,.0-9_"}],
            },
        ),
        (
            (
                "service topic-create --project project1 --partitions 42 --replication 4 "
                + "--cleanup-policy compact --min-insync-replicas 3 "
                + "--retention-bytes 1024 --retention 1 service1 topic1"
            ),
            {
                "topic_name": "topic1",
                "partitions": 42,
                "replication": 4,
                "cleanup_policy": "compact",
                "min_insync_replicas": 3,
                "retention_bytes": 1024,
                "retention_hours": 1,
                "tags": [],
            },
        ),
        (
            (
                "service topic-create --project project1 --partitions 1 --replication 2 "
                + "--retention 1 --retention-ms 123 service1 topic1"
            ),
            {
                "topic_name": "topic1",
                "cleanup_policy": "delete",
                "partitions": 1,
                "replication": 2,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": 1,
                "config": {"retention_ms": 123},
                "tags": [],
            },
        ),
        (
            (
                "service topic-create --project project1 --partitions 1 --replication 2 "
                + "--remote-storage-enable --local-retention-bytes 10 --local-retention-ms 100 service1 topic1"
            ),
            {
                "topic_name": "topic1",
                "cleanup_policy": "delete",
                "partitions": 1,
                "replication": 2,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "config": {
                    "remote_storage_enable": True,
                    "local_retention_bytes": 10,
                    "local_retention_ms": 100,
                },
                "tags": [],
            },
        ),
        (
            (
                "service topic-create --project project1 --partitions 1 --replication 2 "
                + "--remote-storage-disable service1 topic1"
            ),
            {
                "topic_name": "topic1",
                "cleanup_policy": "delete",
                "partitions": 1,
                "replication": 2,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "config": {
                    "remote_storage_enable": False,
                },
                "tags": [],
            },
        ),
    ],
)
def test_service_topic_create(command_line: str, expected_post_data: Mapping[str, str | int | None]) -> None:
    client = AivenClient("")
    session = MagicMock(spec=Session)
    session.post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={}), content=b"{}", reason="OK")
    client.session = session
    cli = build_aiven_cli(client)
    assert cli.run(args=command_line.split(" ")) is None
    session.post.assert_called_once_with(
        "/v1/project/project1/service/service1/topic",
        headers=ANY,
        params=ANY,
        data=ANY,  # checked below
    )
    data_dict = json.loads(session.post.call_args_list[0].kwargs["data"])
    assert data_dict == expected_post_data


@pytest.mark.parametrize(
    "command_line, expected_put_data",
    [
        (
            (
                "service topic-update --project project1 --partitions 42 --replication 3 "
                + "--retention 11 --retention-bytes 500 service1 topic1"
            ),
            {
                "min_insync_replicas": None,
                "partitions": 42,
                "replication": 3,
                "retention_bytes": 500,
                "retention_hours": 11,
            },
        ),
        (
            (
                "service topic-update --project project1 --partitions 42 "
                + "--untag key-_1 --untag key123 --tag key3=az,.0-9_ --tag key234=foo service1 topic1"
            ),
            {
                "min_insync_replicas": None,
                "partitions": 42,
                "replication": None,
                "retention_bytes": None,
                "retention_hours": None,
                "tags": [{"key": "key3", "value": "az,.0-9_"}, {"key": "key234", "value": "foo"}],
            },
        ),
        (
            ("service topic-update --project project1 --partitions 1 --retention 1 --retention-ms 123 service1 topic1"),
            {
                "partitions": 1,
                "replication": None,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": 1,
                "config": {"retention_ms": 123},
            },
        ),
        (
            (
                "service topic-update --project project1 --partitions 1 --replication 2 "
                + "--remote-storage-enable --local-retention-bytes 10 --local-retention-ms 100 service1 topic1"
            ),
            {
                "partitions": 1,
                "replication": 2,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "config": {
                    "remote_storage_enable": True,
                    "local_retention_bytes": 10,
                    "local_retention_ms": 100,
                },
            },
        ),
        (
            (
                "service topic-update --project project1 --partitions 1 --replication 2 "
                + "--remote-storage-disable service1 topic1"
            ),
            {
                "partitions": 1,
                "replication": 2,
                "min_insync_replicas": None,
                "retention_bytes": None,
                "retention_hours": None,
                "config": {
                    "remote_storage_enable": False,
                },
            },
        ),
    ],
)
def test_service_topic_update(command_line: str, expected_put_data: Mapping[str, str | int | None]) -> None:
    class TestAivenClient(AivenClient):
        def __init__(self) -> None:
            super().__init__("")

        def get_service_topic(self, project: str, service: str, topic: str) -> Mapping:
            return {}

    client = TestAivenClient()
    session = MagicMock(spec=Session)
    session.put.return_value = MagicMock(
        status_code=200, json=MagicMock(return_value={"message": "updated"}), content=b'{"message":"updated"}', reason="OK"
    )
    client.session = session
    cli = build_aiven_cli(client)
    assert cli.run(args=command_line.split(" ")) is None
    session.put.assert_called_once_with(
        "/v1/project/project1/service/service1/topic/topic1",
        headers=ANY,
        params=ANY,
        data=ANY,  # checked below
    )
    data_dict = json.loads(session.put.call_args_list[0].kwargs["data"])
    assert data_dict == expected_put_data


def test_service_create_from_pitr() -> None:
    AivenCLI().run(
        args=[
            "service",
            "create",
            "service-fork",
            "--service-type",
            "pg",
            "--plan",
            "business-4",
            "--service-to-fork-from",
            "service",
            "--recovery-target-time",
            "2023-01-20 11:38:49.926085+00:00",
        ]
    )


def test_help() -> None:
    AivenCLI().run(args=["help"])


def test_project_generate_sbom(caplog: LogCaptureFixture) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient(base_url=""))

    # Call with unsupported output extension
    assert (
        build_aiven_cli(aiven_client).run(args=["project", "generate-sbom", "--project", "123foo", "--output", "bar"]) == 1
    )
    assert "unsupported output extension. please, use one from this list: ['csv', 'spdx']" in caplog.text.lower()
    caplog.clear()

    # Valid call, but the API doesn't return what we expect
    aiven_client.get_project_sbom_download_url.return_value = {"foo": "bar"}
    assert (
        build_aiven_cli(aiven_client).run(args=["project", "generate-sbom", "--project", "123foo", "--output", "csv"]) == 1
    )
    assert "cannot retrieve a sbom download url from server" in caplog.text.lower()
    caplog.clear()

    # Valid call
    aiven_client.get_project_sbom_download_url.return_value = {"download_url": "https://foo.bar"}
    assert (
        build_aiven_cli(aiven_client).run(args=["project", "generate-sbom", "--project", "123foo", "--output", "csv"])
        is None
    )
    assert (
        build_aiven_cli(aiven_client).run(args=["project", "generate-sbom", "--project", "123foo", "--output", "spdx"])
        is None
    )
    assert not caplog.text
    aiven_client.get_project_sbom_download_url.assert_called_with(
        project="123foo",
        output_format="spdx",
    )


def test_create_user_config() -> None:
    cli = AivenCLI()
    cli.args = Namespace(
        user_config=["first.second.third=1", "first.second.with.dot=2", "main=3"],
        user_option_remove=["first.second.thirdaway", "foo"],
    )
    schema = {
        "type": "object",
        "properties": {
            "first": {
                "type": "object",
                "properties": {
                    "second": {
                        "type": "object",
                        "properties": {
                            "third": {
                                "type": "integer",
                            },
                            "thirdaway": {
                                "type": ["null", "integer"],
                            },
                            "with.dot": {
                                "type": "integer",
                            },
                        },
                    }
                },
            },
            "foo": {
                "type": ["integer", "null"],
            },
            "main": {
                "type": "integer",
            },
        },
    }
    config = cli.create_user_config(schema)
    assert config == {
        "first": {
            "second": {
                "third": 1,
                "thirdaway": None,
                "with.dot": 2,
            }
        },
        "foo": None,
        "main": 3,
    }


@pytest.mark.parametrize(
    ("user_config_args,config_type,expected_value"),
    [
        ('[{"description":"test","network":"0.0.0.0/0"}]', "array", [{"description": "test", "network": "0.0.0.0/0"}]),
        (
            '[{"description":"test","network":"0.0.0.0/0"},{"description":"test2","network":"100.1.0.0/16"}]',
            "array",
            [{"description": "test", "network": "0.0.0.0/0"}, {"description": "test2", "network": "100.1.0.0/16"}],
        ),
        (
            '[{"description":"test","network":"0.0.0.0/0"},"0.0.0.0"]',
            "array",
            [{"description": "test", "network": "0.0.0.0/0"}, "0.0.0.0"],
        ),
        ("['0.0.0.0','0.0.0/8']", "array", ["0.0.0.0", "0.0.0/8"]),
        ("123", "integer", 123),
        ("10.0", "number", 10.0),
        ("false", "boolean", False),
    ],
)
def test_convert_str_to_value(user_config_args: str, config_type: str, expected_value: str | dict) -> None:
    cli = AivenCLI()
    cli.args = Namespace()
    schema = {
        "type": config_type,
        "title": "Test",
        "description": "Just for test",
        "items": {
            "type": ["string", "object"],
            "title": "",
            "example": "test",
            "maxLength": 43,
            "properties": {
                "description": {
                    "type": "string",
                    "title": "Test description",
                    "example": "test description",
                    "maxLength": 1024,
                },
                "network": {},
            },
            "required": ["test"],
            "additionalProperties": False,
        },
        "default": ["test"],
        "maxItems": 1024,
        "property_parts": ["test"],
    }
    converted_value = convert_str_to_value(schema, user_config_args)
    assert converted_value == expected_value


@pytest.mark.parametrize(
    ("user_config_args,config_type,error_message"),
    [
        ("0.0.0.0/8,0.0.0.0", "dict", "Support for option value type(s) 'dict' not implemented"),
        ("True", "boolean", "Invalid boolean value 'True': expected one of 1, 0, true, false"),
        # ("")
    ],
)
def test_convert_str_to_value_fails(user_config_args: str, config_type: str, error_message: str) -> None:
    schema = {
        "type": config_type,
        "title": "Test",
        "description": "Just for test",
        "items": {
            "type": ["string", "object"],
            "title": "",
            "example": "test",
            "maxLength": 43,
            "properties": {
                "description": {
                    "type": "string",
                    "title": "Test description",
                    "example": "test description",
                    "maxLength": 1024,
                },
                "network": {},
            },
            "required": ["test"],
            "additionalProperties": False,
        },
        "default": ["test"],
        "maxItems": 1024,
        "property_parts": ["test"],
    }
    with pytest.raises(UserError) as excinfo:
        convert_str_to_value(schema, user_config_args)
    assert str(excinfo.value).startswith(error_message)


def patched_get_auth_token() -> str:
    return "token"


def build_aiven_cli(client: AivenClient) -> AivenCLI:
    cli = AivenCLI(client_factory=mock.Mock(spec_set=ClientFactory, return_value=client))
    cli._get_auth_token = patched_get_auth_token  # type: ignore
    return cli


def test_service_task_create_migration_check() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.create_service_task.return_value = {
        "message": "created",
        "task": {
            "create_time": "2021-08-13T08:00:45Z",
            "result": "",
            "success": None,
            "task_id": "79803598-d09a-44bf-ae2b-34aad942f4e8",
            "task_type": "mysql_migration_check",
        },
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "task-create",
            "--operation",
            "migration_check",
            "--project",
            "test",
            "--source-service-uri",
            "mysql://root:password@source-mysql-server:3306/",
            "--ignore-dbs",
            "db1",
            "target-mysql-service-1",
        ]
    )
    aiven_client.create_service_task.assert_called_with(
        project="test",
        service="target-mysql-service-1",
        body={
            "task_type": "migration_check",
            "migration_check": {
                "source_service_uri": "mysql://root:password@source-mysql-server:3306/",
                "ignore_dbs": "db1",
            },
        },
    )


def test_service_task_get_migration_check() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.get_service_task.return_value = {
        "create_time": "2021-08-13T07:10:35Z",
        "ignore_dbs": "defaultdb",
        "result": "aiven_mysql_migrate.exceptions.NothingToMigrateException: No databases to migrate",
        "success": False,
        "task_id": "f25eac03-25f7-4de2-be6a-eb476fec1730",
        "task_type": "mysql_migration_check",
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "task-get",
            "--task-id",
            "f25eac03-25f7-4de2-be6a-eb476fec1730",
            "--project",
            "test",
            "target-mysql-service-1",
        ]
    )
    aiven_client.get_service_task.assert_called_with(
        project="test", service="target-mysql-service-1", task_id="f25eac03-25f7-4de2-be6a-eb476fec1730"
    )


def test_version_eol_check() -> None:
    fake_eol_time = datetime(2021, 9, 10, tzinfo=timezone.utc)

    fake_time_safe = fake_eol_time - EOL_ADVANCE_WARNING_TIME - timedelta(days=1)
    fake_time_soon = fake_eol_time - EOL_ADVANCE_WARNING_TIME + timedelta(days=1)

    aiven_client = mock.Mock(spec_set=AivenClient)
    service_type = "pg"
    service_version = "9.6"
    aiven_client.get_service_versions.return_value = [
        {
            "service_type": service_type,
            "major_version": service_version,
            "aiven_end_of_life_time": "2021-09-10T00:00:00Z",
            "availability_end_time": "2021-06-12T00:00:00Z",
        }
    ]

    cli = AivenCLI(aiven_client)
    cli.client = aiven_client
    cli.confirm = mock.Mock()  # type: ignore

    # Test current time < EOL_WARNING time
    with mock.patch("aiven.client.cli.get_current_date", return_value=fake_time_safe):
        cli._do_version_eol_check(service_type, service_version)
        cli.confirm.assert_not_called()  # No confirmation should have been asked

    # Test current time > EOL_WARNING
    with mock.patch("aiven.client.cli.get_current_date", return_value=fake_time_soon):
        cli._do_version_eol_check(service_type, service_version)
        cli.confirm.assert_called()  # Confirmation should have been asked


def test_create_service_connection_pool() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.update_service_connection_pool.return_value = {"message": "created"}

    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "connection-pool-create",
            "--project",
            "testproject",
            "--dbname",
            "defaultdb",
            "--pool-name",
            "foo",
            "--pool-size=23",
            "--username",
            "avnadmin",
            "pg-foo-bar",
        ]
    )

    aiven_client.create_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname="defaultdb",
        username="avnadmin",
        pool_size=23,
        pool_mode=None,
    )

    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "connection-pool-create",
            "--project",
            "testproject",
            "--dbname",
            "defaultdb",
            "--pool-name",
            "bar",
            "pg-foo-bar",
        ]
    )

    aiven_client.create_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="bar",
        dbname="defaultdb",
        username=None,
        pool_size=None,
        pool_mode=None,
    )


def test_update_service_connection_pool() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.update_service_connection_pool.return_value = {"message": "updated"}

    # pin
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "connection-pool-update",
            "--project",
            "testproject",
            "--pool-name",
            "foo",
            "--username",
            "avnadmin",
            "pg-foo-bar",
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname=None,
        username="avnadmin",
        pool_size=None,
        pool_mode=None,
    )

    # unpin
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "connection-pool-update",
            "--project",
            "testproject",
            "--pool-name",
            "foo",
            "--username",
            "",
            "pg-foo-bar",
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname=None,
        username=None,
        pool_size=None,
        pool_mode=None,
    )

    # leave username as is, change pool-size instead
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "connection-pool-update",
            "--project",
            "testproject",
            "--pool-name",
            "foo",
            "--pool-size",
            "42",
            "pg-foo-bar",
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject", service="pg-foo-bar", pool_name="foo", dbname=None, pool_size=42, pool_mode=None
    )


@contextmanager
def mock_config(return_value: Any) -> Iterator[None]:
    with mock.patch("aiven.client.argx.Config", side_effect=lambda _: return_value):
        yield


def test_get_project(caplog: LogCaptureFixture) -> None:
    # https://github.com/aiven/aiven-client/issues/246
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.get_services.side_effect = lambda project: []
    args = ["service", "list"]
    with mock_config({}):
        assert build_aiven_cli(aiven_client).run(args=args) == 1
    assert "specify project" in caplog.text.lower()
    caplog.clear()
    assert build_aiven_cli(aiven_client).run(args=args + ["--project", "project_0"]) is None
    assert not caplog.text
    with mock_config({"default_project": "project_1"}):
        assert build_aiven_cli(aiven_client).run(args=args) is None
    assert not caplog.text


def test_user_logout() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    assert build_aiven_cli(aiven_client).run(["user", "logout"]) is None
    aiven_client.access_token_revoke.assert_called()

    aiven_client = mock.Mock(spec_set=AivenClient)
    assert build_aiven_cli(aiven_client).run(["user", "logout", "--no-token-revoke"]) is None
    aiven_client.access_token_revoke.assert_not_called()


def test_oauth2_clients_list() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    aiven_client.list_oauth2_clients.return_value = {
        "oauth2_clients": [
            {
                "client_id": str(uuid.uuid4()),
                "name": "dummy-client",
                "description": "dummy client",
            }
        ]
    }

    build_aiven_cli(aiven_client).run(args=["account", "oauth2-client", "list", "a2313127"])

    aiven_client.list_oauth2_clients.assert_called_with("a2313127")


def test_oauth2_client_get() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.get_oauth2_client.return_value = {
        "client_id": oauth2_client_id,
        "name": "dummy-client",
        "description": "dummy client",
    }

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "get", "a2313127", "--oauth2-client-id", oauth2_client_id]
    )

    aiven_client.get_oauth2_client.assert_called_with("a2313127", oauth2_client_id)


def test_oauth2_client_update() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.update_oauth2_client.return_value = {
        "client_id": oauth2_client_id,
        "name": "dummy-client",
        "description": "dummy client",
    }

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "update", "a2313127", "--oauth2-client-id", oauth2_client_id, "--name", "new-name"]
    )

    aiven_client.update_oauth2_client.assert_called_with(
        account_id="a2313127",
        client_id=oauth2_client_id,
        name="new-name",
        description=None,
    )


def test_oauth2_client_remove() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.delete_oauth2_client.return_value = {}

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "delete", "a2313127", "--oauth2-client-id", oauth2_client_id]
    )

    aiven_client.delete_oauth2_client.assert_called_with("a2313127", oauth2_client_id)


def test_oauth2_client_redirects_list() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.list_oauth2_client_redirects.return_value = {"redirects": []}

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "redirect-list", "a2313127", "--oauth2-client-id", oauth2_client_id]
    )

    aiven_client.list_oauth2_client_redirects.assert_called_with("a2313127", oauth2_client_id)


def test_oauth2_client_redirect_create() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.create_oauth2_client_redirect.return_value = {}

    build_aiven_cli(aiven_client).run(
        args=[
            "account",
            "oauth2-client",
            "redirect-create",
            "a2313127",
            "--oauth2-client-id",
            oauth2_client_id,
            "--redirect-uri",
            "https://example.com",
        ]
    )

    aiven_client.create_oauth2_client_redirect.assert_called_with("a2313127", oauth2_client_id, "https://example.com")


def test_oauth2_client_redirect_delete() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.delete_oauth2_client_redirect.return_value = {}

    build_aiven_cli(aiven_client).run(
        args=[
            "account",
            "oauth2-client",
            "redirect-delete",
            "a2313127",
            "--oauth2-client-id",
            oauth2_client_id,
            "--redirect-uri-id",
            "123",
        ]
    )

    aiven_client.delete_oauth2_client_redirect.assert_called_with("a2313127", oauth2_client_id, "123")


def test_oauth2_client_secrets_list() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.list_oauth2_client_secrets.return_value = {"secrets": []}

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "secret-list", "a2313127", "--oauth2-client-id", oauth2_client_id]
    )

    aiven_client.list_oauth2_client_secrets.assert_called_with("a2313127", oauth2_client_id)


def test_oauth2_client_secret_create() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())

    aiven_client.create_oauth2_client_secret.return_value = {
        "secret_id": secret_id,
        "secret": "random-secret-string",
        "secret_suffix": "string",
    }

    build_aiven_cli(aiven_client).run(
        args=["account", "oauth2-client", "secret-create", "a2313127", "--oauth2-client-id", oauth2_client_id]
    )

    aiven_client.create_oauth2_client_secret.assert_called_with("a2313127", oauth2_client_id)


def test_oauth2_client_secret_delete() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    oauth2_client_id = str(uuid.uuid4())

    aiven_client.delete_oauth2_client_secret.return_value = {}

    build_aiven_cli(aiven_client).run(
        args=[
            "account",
            "oauth2-client",
            "secret-delete",
            "a2313127",
            "--oauth2-client-id",
            oauth2_client_id,
            "--secret-id",
            "123",
        ]
    )

    aiven_client.delete_oauth2_client_secret.assert_called_with("a2313127", oauth2_client_id, "123")


def test_create_oauth2_client() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    created_client_id = None

    def _create_client(account_id: str, name: str, description: str | None = None) -> Mapping:
        nonlocal created_client_id

        created_client_id = str(uuid.uuid4())

        return {
            "client_id": created_client_id,
            "name": name,
            "description": description,
        }

    def _create_redirect(account_id: str, client_id: str, uri: str) -> Mapping:
        return {
            "redirect_id": 127,
            "redirect_uri": uri,
        }

    aiven_client.create_oauth2_client.side_effect = _create_client
    aiven_client.create_oauth2_client_redirect.side_effect = _create_redirect
    aiven_client.create_oauth2_client_secret.return_value = {"secret_id": str(uuid.uuid4()), "secret": "MySecret"}

    build_aiven_cli(aiven_client).run(
        args=[
            "account",
            "oauth2-client",
            "create",
            "a2313127",
            "--name",
            "MyOAuth2App",
            "--redirect-uri",
            "https://example.com/redirect",
            "--description",
            "My description",
        ]
    )

    aiven_client.create_oauth2_client.assert_called_with(
        "a2313127",
        name="MyOAuth2App",
        description="My description",
    )

    aiven_client.create_oauth2_client_redirect.assert_called_with(
        "a2313127",
        created_client_id,
        "https://example.com/redirect",
    )

    aiven_client.create_oauth2_client_secret.assert_called_with(
        "a2313127",
        created_client_id,
    )


def test_clickhouse_database_create() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.clickhouse_database_create.return_value = {"message": "created"}
    args = ["service", "clickhouse", "database", "create", "--project=myproj", "myservice", "mydatabase"]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.clickhouse_database_create.assert_called_with(project="myproj", service="myservice", database="mydatabase")


def test_clickhouse_database_delete() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.clickhouse_database_delete.return_value = {"message": "deleting"}
    args = ["service", "clickhouse", "database", "delete", "--project=myproj", "myservice", "mydatabase"]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.clickhouse_database_delete.assert_called_with(project="myproj", service="myservice", database="mydatabase")


def test_clickhouse_database_list() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.clickhouse_database_list.return_value = [
        {"name": "mydatabase", "engine": "Replicated", "state": "ok", "tables": []}
    ]
    args = ["service", "clickhouse", "database", "list", "--project=myproj", "myservice"]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.clickhouse_database_list.assert_called_with(project="myproj", service="myservice")


def test_clickhouse_table_list() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    tables = [
        {
            "name": "mytable",
            "uuid": str(uuid.UUID(int=0)),
            "engine": "ReplicatedMergeTree",
            "total_rows": 10,
            "total_bytes": 100,
            "state": "ok",
        }
    ]
    aiven_client.clickhouse_database_list.return_value = [
        {"name": "mydatabase", "engine": "Replicated", "state": "ok", "tables": tables}
    ]
    args = ["service", "clickhouse", "table", "list", "--project=myproj", "myservice", "mydatabase"]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.clickhouse_database_list.assert_called_with(project="myproj", service="myservice")


def test_static_ips_list(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.list_static_ip_addresses.return_value = [
        {
            "static_ip_address_id": "".join(random.choices(string.ascii_letters, k=16)).lower(),
            "state": "created",
            "cloud_name": "".join(random.choices(string.ascii_letters, k=10)).lower(),
            "service_name": "null",
            "ip_address": f"10.0.0.{i}",
        }
        for i in range(70)
    ]

    build_aiven_cli(aiven_client).run(args=["static-ip", "list", "--project", "test"])
    stdout, _ = capsys.readouterr()
    assert "10.0.0.0" in stdout
    assert "10.0.0.69" in stdout


def dummy_client_for_vpc_tests(cloud_with_vpc: str | None = None) -> AivenCLI:
    cli = AivenCLI()

    class Client:
        def list_project_vpcs(self, project: str) -> dict:
            if cloud_with_vpc:
                return {"vpcs": [{"cloud_name": cloud_with_vpc}]}
            else:
                return {"vpcs": []}

    cli.client = cast(AivenClient, Client())
    return cli


def test_cloud_has_vpc_user_said_nothing() -> None:
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(["service", "create", "--project=my-name", "--cloud=my-cloud", "--service-type=pg", "service-name"])
    with pytest.raises(UserError) as excinfo:
        cli._get_service_project_vpc_id()
    assert str(excinfo.value).startswith("Cloud my-cloud has a VPC")


def test_cloud_has_vpc_user_said_nothing_and_no_cloud_switch() -> None:
    """When the user does not specify --cloud, we assume an "earlier" cloud will be re-used

    (and that the user is OK with the configuration of that cloud)
    """
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(["service", "create", "--project=my-name", "--service-type=pg", "service-name"])
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id is UNDEFINED


def test_cloud_has_vpc_user_said_no_vpc() -> None:
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--no-project-vpc",
            "service-name",
        ]
    )
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id is None


def test_cloud_has_vpc_user_gave_vpc_id() -> None:
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--project-vpc-id=27",
            "service-name",
        ]
    )
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id == "27"


def test_cloud_has_vpc_user_gave_both_switches() -> None:
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--no-project-vpc",
            "--project-vpc-id=27",
            "service-name",
        ]
    )
    with pytest.raises(UserError) as excinfo:
        cli._get_service_project_vpc_id()
    assert str(excinfo.value).startswith("Only one of --project-vpc-id")


def test_cloud_has_no_vpc_user_said_nothing() -> None:
    cli = dummy_client_for_vpc_tests()
    cli.parse_args(["service", "create", "--project=my-name", "--cloud=my-cloud", "--service-type=pg", "service-name"])
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id is UNDEFINED


def test_cloud_has_no_vpc_user_said_no_vpc() -> None:
    cli = dummy_client_for_vpc_tests()
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--no-project-vpc",
            "service-name",
        ]
    )
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id is None


def test_cloud_has_no_vpc_user_gave_vpc_id() -> None:
    cli = dummy_client_for_vpc_tests()
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--project-vpc-id=27",
            "service-name",
        ]
    )
    vpc_id = cli._get_service_project_vpc_id()
    assert vpc_id == "27"


def test_cloud_has_no_vpc_user_gave_both_switches() -> None:
    cli = dummy_client_for_vpc_tests()
    cli.parse_args(
        [
            "service",
            "create",
            "--project=my-name",
            "--cloud=my-cloud",
            "--service-type=pg",
            "--no-project-vpc",
            "--project-vpc-id=27",
            "service-name",
        ]
    )
    with pytest.raises(UserError) as excinfo:
        cli._get_service_project_vpc_id()
    assert str(excinfo.value).startswith("Only one of --project-vpc-id")


def test_get_service_type() -> None:
    cli = AivenCLI()
    cli.parse_args(
        [
            "service",
            "create",
            "--cloud",
            "my-cloud",
            "--service-type",
            "pg",
            "--plan",
            "business-4",
            "service-name",
        ]
    )
    assert cli._get_service_type() == "pg"
    cli = AivenCLI()
    cli.parse_args(
        [
            "service",
            "create",
            "--cloud",
            "my-cloud",
            "--service-type",
            "pg:business-4",
            "service-name",
        ]
    )
    assert cli._get_service_type() == "pg"


def test_get_service_plan() -> None:
    cli = AivenCLI()
    cli.parse_args(
        [
            "service",
            "create",
            "--cloud",
            "my-cloud",
            "--service-type",
            "pg",
            "--plan",
            "business-4",
            "service-name",
        ]
    )
    assert cli._get_plan() == "business-4"
    cli = AivenCLI()
    cli.parse_args(
        [
            "service",
            "create",
            "--cloud",
            "my-cloud",
            "--service-type",
            "pg:business-4",
            "service-name",
        ]
    )
    assert cli._get_plan() == "business-4"
    with pytest.raises(argx.UserError, match="No subscription plan given"):
        cli = AivenCLI()
        cli.parse_args(
            [
                "service",
                "create",
                "--cloud",
                "my-cloud",
                "--service-type",
                "pg",
                "service-name",
            ]
        )
        cli._get_plan()


def test_organizations_list(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    aiven_client.get_organizations.return_value = [
        {
            "organization_id": "o2131231",
            "organization_name": "My Org",
            "account_id": "a23123",
            "tier": "business",
            "create_time": "2023-07-13T08:00:45Z",
            "update_time": "2023-07-13T08:00:45Z",
        }
    ]

    build_aiven_cli(aiven_client).run(args=["organization", "list"])
    aiven_client.get_organizations.assert_called_with()

    captured = capsys.readouterr()
    assert "My Org" in captured.out
    assert "business" in captured.out


def test_project_create__parent_id_required() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    with pytest.raises(SystemExit) as excinfo:
        build_aiven_cli(aiven_client).run(
            args=[
                "project",
                "create",
                "new-project",
            ]
        )
    assert excinfo.value.code == EXIT_CODE_INVALID_USAGE


def test_project_create__parent_id_requested_correctly() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    account_id = "a1231231"
    project_name = "new-project"

    aiven_client.create_project.return_value = {
        "project_id": "p123123124",
        "project_name": project_name,
        "default_cloud": "my-default-cloud",
        "billing_currency": "USD",
        "vat_id": "",
        "billing_extra_text": "",
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "project",
            "create",
            "--parent-id",
            account_id,
            project_name,
        ]
    )
    aiven_client.create_project.assert_called_with(
        account_id=account_id,
        project=project_name,
        billing_group_id=None,
        cloud=None,
        copy_from_project=None,
        tech_emails=None,
        use_source_project_billing_group=False,
    )


def test_project_create__parent_id_as_org_id_requested_correctly() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    organization_id = "org2131231"
    account_id = "a1231231"
    project_name = "new-project-name"

    aiven_client.get_organization.return_value = {
        "organization_id": organization_id,
        "organization_name": "My Org",
        "account_id": account_id,
        "tier": "business",
        "create_time": "2023-07-13T08:00:45Z",
        "update_time": "2023-07-13T08:00:45Z",
    }

    aiven_client.create_project.return_value = {
        "project_id": "p123123124",
        "project_name": project_name,
        "default_cloud": "my-default-cloud",
        "billing_currency": "USD",
        "vat_id": "",
        "billing_extra_text": "",
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "project",
            "create",
            "--parent-id",
            organization_id,
            project_name,
        ]
    )
    aiven_client.create_project.assert_called_with(
        account_id=account_id,
        project=project_name,
        billing_group_id=None,
        cloud=None,
        copy_from_project=None,
        tech_emails=None,
        use_source_project_billing_group=False,
    )


def test_project_update__parent_id_requested_correctly() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    account_id = "a1231231"
    project_name = "my-project-name"
    new_project_name = "new-project-name"

    aiven_client.update_project.return_value = {
        "project_id": "p123123124",
        "project_name": new_project_name,
        "default_cloud": "my-default-cloud",
        "billing_currency": "USD",
        "vat_id": "",
        "billing_extra_text": "",
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "project",
            "update",
            "--project",
            project_name,
            "--parent-id",
            account_id,
            "--name",
            new_project_name,
        ]
    )
    aiven_client.update_project.assert_called_with(
        new_project_name=new_project_name,
        account_id=account_id,
        cloud=None,
        project=project_name,
        tech_emails=None,
    )


def test_project_update__parent_id_as_org_id_requested_correctly() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    organization_id = "org2131231"
    account_id = "a1231231"
    project_name = "my-project-name"
    new_project_name = "new-project-name"

    aiven_client.get_organization.return_value = {
        "organization_id": organization_id,
        "organization_name": "My Org",
        "account_id": account_id,
        "tier": "business",
        "create_time": "2023-07-13T08:00:45Z",
        "update_time": "2023-07-13T08:00:45Z",
    }

    aiven_client.update_project.return_value = {
        "project_id": "p123123124",
        "project_name": new_project_name,
        "default_cloud": "my-default-cloud",
        "billing_currency": "USD",
        "vat_id": "",
        "billing_extra_text": "",
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "project",
            "update",
            "--project",
            project_name,
            "--parent-id",
            organization_id,
            "--name",
            new_project_name,
        ]
    )
    aiven_client.update_project.assert_called_with(
        new_project_name=new_project_name,
        account_id=account_id,
        cloud=None,
        project=project_name,
        tech_emails=None,
    )


def test_custom_files_list(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = {
        "custom_files": [
            {
                "create_time": "2023-01-01T00:00:00Z",
                "file_id": "a4d83aaa-35ae-51b4-b500-81e743bfe906",
                "filename": "foo1",
                "filesize": 25,
                "filetype": "synonyms",
                "service_reference": "custom/synonyms/foo1",
                "update_time": "2023-01-01T00:00:00Z",
            }
        ]
    }

    aiven_client.custom_file_list.return_value = return_value

    build_aiven_cli(aiven_client).run(args=["service", "custom-file", "list", "--project", "test", "foo"])
    aiven_client.custom_file_list.assert_called_with(project="test", service="foo")
    captured = capsys.readouterr()
    assert json.loads(captured.out) == return_value


def test_custom_files_get_stdout(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = b"foo => bar"

    aiven_client.custom_file_get.return_value = return_value

    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "custom-file",
            "get",
            "--project",
            "test",
            "--file_id",
            "a4d83aaa-35ae-51b4-b500-81e743bfe906",
            "--stdout_write",
            "foo",
        ]
    )
    aiven_client.custom_file_get.assert_called_with(
        project="test", service="foo", file_id="a4d83aaa-35ae-51b4-b500-81e743bfe906"
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == return_value.decode("utf-8")


def test_custom_files_get_file(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = b"foo => bar"

    aiven_client.custom_file_get.return_value = return_value
    with tempfile.NamedTemporaryFile(delete=False) as f_temp:
        # Closing file so Windows could let cli open it
        file_name = f_temp.name
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "custom-file",
            "get",
            "--project",
            "test",
            "--file_id",
            "a4d83aaa-35ae-51b4-b500-81e743bfe906",
            "--target_filepath",
            file_name,
            "foo",
        ]
    )
    aiven_client.custom_file_get.assert_called_with(
        project="test", service="foo", file_id="a4d83aaa-35ae-51b4-b500-81e743bfe906"
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == ""
    with open(file_name, "rb") as f:
        assert f.read() == return_value


def test_custom_files_get_both(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = b"foo => bar"

    aiven_client.custom_file_get.return_value = return_value
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Closing file so Windows could let cli open it
        file_name = f.name
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "custom-file",
            "get",
            "--project",
            "test",
            "--file_id",
            "a4d83aaa-35ae-51b4-b500-81e743bfe906",
            "--target_filepath",
            file_name,
            "--stdout_write",
            "foo",
        ]
    )
    aiven_client.custom_file_get.assert_called_with(
        project="test", service="foo", file_id="a4d83aaa-35ae-51b4-b500-81e743bfe906"
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == return_value.decode("utf-8")
    with open(file_name, "rb") as f:
        assert f.read() == return_value


def test_custom_files_get_none(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = b"foo => bar"

    aiven_client.custom_file_get.return_value = return_value
    aiven_cli = build_aiven_cli(aiven_client)
    aiven_cli.run(
        args=[
            "service",
            "custom-file",
            "get",
            "--project",
            "test",
            "--file_id",
            "a4d83aaa-35ae-51b4-b500-81e743bfe906",
            "foo",
        ]
    )
    aiven_client.custom_file_get.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out.strip() == ""
    with pytest.raises(argx.UserError):
        aiven_cli.service__custom_file__get()


def test_custom_files_upload(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = {
        "file_id": "d19878d5-2726-5773-81cb-ff61562c892c",
        "message": "created",
        "service_reference": "custom/synonyms/foo2",
    }

    aiven_client.custom_file_upload.return_value = return_value
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Closing file so Windows could let cli open it
        file_name = f.name
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "custom-file",
            "upload",
            "--project",
            "test",
            "--file_path",
            file_name,
            "--file_type",
            "synonyms",
            "--file_name",
            "foo2",
            "foo",
        ]
    )
    # Can't check args as the file is reopened
    aiven_client.custom_file_upload.assert_called_once()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip()) == return_value


def test_custom_files_update(capsys: CaptureFixture[str]) -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)

    return_value = {
        "file_id": "d19878d5-2726-5773-81cb-ff61562c892c",
        "message": "updated",
        "service_reference": "custom/synonyms/foo2",
    }

    aiven_client.custom_file_update.return_value = return_value
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Closing file so Windows could let cli open it
        file_name = f.name
    build_aiven_cli(aiven_client).run(
        args=[
            "service",
            "custom-file",
            "update",
            "--project",
            "test",
            "--file_path",
            file_name,
            "--file_id",
            "d19878d5-2726-5773-81cb-ff61562c892c",
            "foo",
        ]
    )
    # Can't check args as the file is reopened
    aiven_client.custom_file_update.assert_called_once()
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip()) == return_value


def test_sustainability__service_plan_emissions_project() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.sustainability_service_plan_emissions_project.return_value = {
        "emissions": {"co2eq_mtons": "0.25", "energy_kwh": "639.50"}
    }
    args = [
        "sustainability",
        "service-plan-emissions-project",
        "--project=myproj",
        "--service-type=kafka",
        "--plan=business-32",
        "--cloud=google-europe-west1",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.sustainability_service_plan_emissions_project.assert_called_with(
        project="myproj", service_type="kafka", plan="business-32", cloud="google-europe-west1"
    )


def test_sustainability__project_emissions_estimate() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.sustainability_project_emissions_estimate.return_value = {
        "emissions": {"co2eq_mtons": "0.50", "energy_kwh": "1279.00"}
    }
    args = [
        "sustainability",
        "project-emissions-estimate",
        "--project=myproj",
        "--since=20230901",
        "--until=20231001",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.sustainability_project_emissions_estimate.assert_called_with(
        project="myproj",
        since="20230901",
        until="20231001",
    )


def test_byoc_create() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.byoc_create.return_value = {
        "custom_cloud_environment": {
            "cloud_provider": "aws",
            "cloud_region": "eu-north-1",
            "contact_emails": [],
            "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            "deployment_model": "standard",
            "reserved_cidr": "10.1.0.0/20",
            "display_name": "My Byoc Cloud",
            "state": "draft",
        }
    }
    args = [
        "byoc",
        "create",
        "--organization-id=org123456789a",
        "--deployment-model=standard",
        "--cloud-provider=aws",
        "--cloud-region=eu-north-1",
        "--reserved-cidr=10.1.0.0/20",
        "--display-name=My Byoc Cloud",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.byoc_create.assert_called_once_with(
        organization_id="org123456789a",
        deployment_model="standard",
        cloud_provider="aws",
        cloud_region="eu-north-1",
        reserved_cidr="10.1.0.0/20",
        display_name="My Byoc Cloud",
    )


def test_byoc_update() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.byoc_update.return_value = {
        "custom_cloud_environment": {
            "cloud_provider": "aws",
            "cloud_region": "eu-west-2",
            "contact_emails": [],
            "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            "deployment_model": "standard",
            "reserved_cidr": "10.1.0.0/24",
            "display_name": "Another name",
            "state": "draft",
        }
    }
    args = [
        "byoc",
        "update",
        "--organization-id=org123456789a",
        "--byoc-id=d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
        "--cloud-region=eu-west-2",
        "--reserved-cidr=10.1.0.0/24",
        "--display-name=Another name",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.byoc_update.assert_called_once_with(
        organization_id="org123456789a",
        byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
        deployment_model=None,
        cloud_provider=None,
        cloud_region="eu-west-2",
        reserved_cidr="10.1.0.0/24",
        display_name="Another name",
    )


def test_byoc_provision() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.byoc_provision.return_value = {
        "custom_cloud_environment": {
            "cloud_provider": "aws",
            "cloud_region": "eu-west-2",
            "contact_emails": [],
            "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            "deployment_model": "standard",
            "reserved_cidr": "10.1.0.0/24",
            "display_name": "Another name",
            "state": "creating",
        }
    }
    args = [
        "byoc",
        "provision",
        "--organization-id=org123456789a",
        "--byoc-id=d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
        "--aws-iam-role-arn=arn:aws:iam::123456789012:role/role-name",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.byoc_provision.assert_called_once_with(
        organization_id="org123456789a",
        byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
        aws_iam_role_arn="arn:aws:iam::123456789012:role/role-name",
    )


def test_byoc_delete() -> None:
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.byoc_delete.return_value = {"message": "deleting"}
    args = [
        "byoc",
        "delete",
        "--organization-id=org123456789a",
        "--byoc-id=d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
    ]
    build_aiven_cli(aiven_client).run(args=args)
    aiven_client.byoc_delete.assert_called_once_with(
        organization_id="org123456789a",
        byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
    )
