# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client.cli import AivenCLI
from collections import namedtuple
from unittest import mock

import pytest

pytestmark = [pytest.mark.unittest, pytest.mark.all]


def test_cli():
    with pytest.raises(SystemExit) as excinfo:
        AivenCLI().run(args=["--help"])
    assert excinfo.value.code == 0


def test_cloud_list():
    AivenCLI().run(args=["cloud", "list"])


def test_service_plans():
    AivenCLI().run(args=["service", "plans"])


def test_service_types_v():
    AivenCLI().run(args=["service", "types", "-v"])


def test_service_user_create():
    AivenCLI().run(args=["service", "user-create", "service", "--username", "username"])


def test_service_topic_create():
    AivenCLI().run(args=["service", "topic-create", "--partitions", "42", "--replication", "42", "service1", "topic1"])


def test_service_topic_create_with_tags():
    AivenCLI().run(
        args=[
            "service", "topic-create", "--partitions", "42", "--replication", "42", "--tag", "key-_1=value1", "--tag",
            "key2=az,.0-9_", "service1", "topic1"
        ]
    )


def test_service_topic_update():
    AivenCLI().run(
        args=[
            "service", "topic-update", "--partitions", "42", "--untag", "key-_1", "--untag", "key123", "--tag",
            "key3=az,.0-9_", "--tag", "key234=foo", "service1", "topic1"
        ]
    )


def test_help():
    AivenCLI().run(args=["help"])


def test_create_user_config():
    cli = AivenCLI()
    cli.args = namedtuple("args", ["user_config", "user_option_remove"])
    cli.args.user_config = ["first.second.third=1", "first.second.with.dot=2", "main=3"]
    cli.args.user_option_remove = ["first.second.thirdaway", "foo"]
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


@pytest.fixture(name="authenticated_cli")
def fixture_authenticated_cli():
    def patched_get_auth_token():
        return "token"

    cli = AivenCLI()
    cli._get_auth_token = patched_get_auth_token  # pylint: disable=protected-access
    return cli


def test_service_task_create_migration_check(authenticated_cli):
    task_create_response = {
        "message": "created",
        "task": {
            "create_time": "2021-08-13T08:00:45Z",
            "result": "",
            "success": None,
            "task_id": "79803598-d09a-44bf-ae2b-34aad942f4e8",
            "task_type": "mysql_migration_check"
        }
    }

    with mock.patch("aiven.client.client.AivenClient") as cli_client_mock:
        cli_client_mock.return_value.create_service_task.return_value = task_create_response
        authenticated_cli.run(
            args=[
                "service", "task-create", "--operation", "migration_check", "--project", "test", "--source-service-uri",
                "mysql://root:password@source-mysql-server:3306/", "--ignore-dbs", "db1", "target-mysql-service-1"
            ]
        )
        cli_client_mock.return_value.create_service_task.assert_called_with(
            project='test',
            service='target-mysql-service-1',
            body={
                'task_type': 'migration_check',
                'migration_check': {
                    'source_service_uri': 'mysql://root:password@source-mysql-server:3306/',
                    'ignore_dbs': 'db1'
                }
            }
        )


def test_service_task_get_migration_check(authenticated_cli):
    task_get_response = {
        "create_time": "2021-08-13T07:10:35Z",
        "ignore_dbs": "defaultdb",
        "result": "aiven_mysql_migrate.exceptions.NothingToMigrateException: No databases to migrate",
        "success": False,
        "task_id": "f25eac03-25f7-4de2-be6a-eb476fec1730",
        "task_type": "mysql_migration_check"
    }

    with mock.patch("aiven.client.client.AivenClient") as cli_client_mock:
        cli_client_mock.return_value.get_service_task.return_value = task_get_response
        authenticated_cli.run(
            args=[
                "service", "task-get", "--task-id", "f25eac03-25f7-4de2-be6a-eb476fec1730", "--project", "test",
                "target-mysql-service-1"
            ]
        )
        cli_client_mock.return_value.get_service_task.assert_called_with(
            project='test', service='target-mysql-service-1', task_id='f25eac03-25f7-4de2-be6a-eb476fec1730'
        )
