# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client import AivenClient
from aiven.client.cli import AivenCLI, ClientFactory, EOL_ADVANCE_WARNING_TIME
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest


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


def patched_get_auth_token() -> str:
    return "token"


def build_aiven_cli(client: AivenClient) -> AivenCLI:
    cli = AivenCLI(client_factory=mock.Mock(spec_set=ClientFactory, return_value=client))
    cli._get_auth_token = patched_get_auth_token  # pylint: disable=protected-access
    return cli


def test_service_task_create_migration_check():
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.create_service_task.return_value = {
        "message": "created",
        "task": {
            "create_time": "2021-08-13T08:00:45Z",
            "result": "",
            "success": None,
            "task_id": "79803598-d09a-44bf-ae2b-34aad942f4e8",
            "task_type": "mysql_migration_check"
        }
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "service", "task-create", "--operation", "migration_check", "--project", "test", "--source-service-uri",
            "mysql://root:password@source-mysql-server:3306/", "--ignore-dbs", "db1", "target-mysql-service-1"
        ]
    )
    aiven_client.create_service_task.assert_called_with(
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


def test_service_task_get_migration_check():
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.get_service_task.return_value = {
        "create_time": "2021-08-13T07:10:35Z",
        "ignore_dbs": "defaultdb",
        "result": "aiven_mysql_migrate.exceptions.NothingToMigrateException: No databases to migrate",
        "success": False,
        "task_id": "f25eac03-25f7-4de2-be6a-eb476fec1730",
        "task_type": "mysql_migration_check"
    }

    build_aiven_cli(aiven_client).run(
        args=[
            "service", "task-get", "--task-id", "f25eac03-25f7-4de2-be6a-eb476fec1730", "--project", "test",
            "target-mysql-service-1"
        ]
    )
    aiven_client.get_service_task.assert_called_with(
        project='test', service='target-mysql-service-1', task_id='f25eac03-25f7-4de2-be6a-eb476fec1730'
    )


def test_version_eol_check():
    fake_eol_time = datetime(2021, 9, 10, tzinfo=timezone.utc)

    fake_time_safe = fake_eol_time - EOL_ADVANCE_WARNING_TIME - timedelta(days=1)
    fake_time_soon = fake_eol_time - EOL_ADVANCE_WARNING_TIME + timedelta(days=1)

    aiven_client = mock.Mock(spec_set=AivenClient)
    service_type = "pg"
    service_version = "9.6"
    aiven_client.get_service_versions.return_value = [{
        "service_type": service_type,
        "major_version": service_version,
        "aiven_end_of_life_time": "2021-09-10T00:00:00Z",
        "availability_end_time": "2021-06-12T00:00:00Z"
    }]

    cli = AivenCLI(aiven_client)
    cli.client = aiven_client
    cli.confirm = mock.Mock()

    # Test current time < EOL_WARNING time
    with mock.patch("aiven.client.cli.get_current_date", return_value=fake_time_safe):
        cli._do_version_eol_check(service_type, service_version)  # pylint: disable=protected-access
        cli.confirm.assert_not_called()  # No confirmation should have been asked

    # Test current time > EOL_WARNING
    with mock.patch("aiven.client.cli.get_current_date", return_value=fake_time_soon):
        cli._do_version_eol_check(service_type, service_version)  # pylint: disable=protected-access
        cli.confirm.assert_called()  # Confirmation should have been asked


def test_create_service_connection_pool():
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.update_service_connection_pool.return_value = {"message": "created"}

    build_aiven_cli(aiven_client).run(
        args=[
            "service", "connection-pool-create", "--project", "testproject", "--dbname", "defaultdb", "--pool-name", "foo",
            "--pool-size=23", "--username", "avnadmin", "pg-foo-bar"
        ]
    )

    aiven_client.create_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname="defaultdb",
        username="avnadmin",
        pool_size=23,
        pool_mode=None
    )

    build_aiven_cli(aiven_client).run(
        args=[
            "service", "connection-pool-create", "--project", "testproject", "--dbname", "defaultdb", "--pool-name", "bar",
            "pg-foo-bar"
        ]
    )

    aiven_client.create_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="bar",
        dbname="defaultdb",
        username=None,
        pool_size=None,
        pool_mode=None
    )


def test_update_service_connection_pool():
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.update_service_connection_pool.return_value = {"message": "updated"}

    # pin
    build_aiven_cli(aiven_client).run(
        args=[
            "service", "connection-pool-update", "--project", "testproject", "--pool-name", "foo", "--username", "avnadmin",
            "pg-foo-bar"
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname=None,
        username="avnadmin",
        pool_size=None,
        pool_mode=None
    )

    # unpin
    build_aiven_cli(aiven_client).run(
        args=[
            "service", "connection-pool-update", "--project", "testproject", "--pool-name", "foo", "--username", "",
            "pg-foo-bar"
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject",
        service="pg-foo-bar",
        pool_name="foo",
        dbname=None,
        username=None,
        pool_size=None,
        pool_mode=None
    )

    # leave username as is, change pool-size instead
    build_aiven_cli(aiven_client).run(
        args=[
            "service", "connection-pool-update", "--project", "testproject", "--pool-name", "foo", "--pool-size", "42",
            "pg-foo-bar"
        ]
    )

    aiven_client.update_service_connection_pool.assert_called_with(
        project="testproject", service="pg-foo-bar", pool_name="foo", dbname=None, pool_size=42, pool_mode=None
    )
