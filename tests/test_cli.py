# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from aiven.client import AivenClient
from aiven.client.argx import UserError
from aiven.client.cli import AivenCLI, ClientFactory, EOL_ADVANCE_WARNING_TIME
from aiven.client.common import UNDEFINED
from argparse import Namespace
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pytest import CaptureFixture, LogCaptureFixture
from typing import Any, cast, Iterator, Mapping, Optional
from unittest import mock

import pytest
import random
import string
import uuid


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


def test_service_topic_create() -> None:
    AivenCLI().run(args=["service", "topic-create", "--partitions", "42", "--replication", "42", "service1", "topic1"])


def test_service_topic_create_with_tags() -> None:
    AivenCLI().run(
        args=[
            "service",
            "topic-create",
            "--partitions",
            "42",
            "--replication",
            "42",
            "--tag",
            "key-_1=value1",
            "--tag",
            "key2=az,.0-9_",
            "service1",
            "topic1",
        ]
    )


def test_service_topic_update() -> None:
    AivenCLI().run(
        args=[
            "service",
            "topic-update",
            "--partitions",
            "42",
            "--untag",
            "key-_1",
            "--untag",
            "key123",
            "--tag",
            "key3=az,.0-9_",
            "--tag",
            "key234=foo",
            "service1",
            "topic1",
        ]
    )


def test_help() -> None:
    AivenCLI().run(args=["help"])


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


def patched_get_auth_token() -> str:
    return "token"


def build_aiven_cli(client: AivenClient) -> AivenCLI:
    cli = AivenCLI(client_factory=mock.Mock(spec_set=ClientFactory, return_value=client))
    cli._get_auth_token = patched_get_auth_token  # type: ignore # pylint: disable=protected-access
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
        cli._do_version_eol_check(service_type, service_version)  # pylint: disable=protected-access
        cli.confirm.assert_not_called()  # No confirmation should have been asked

    # Test current time > EOL_WARNING
    with mock.patch("aiven.client.cli.get_current_date", return_value=fake_time_soon):
        cli._do_version_eol_check(service_type, service_version)  # pylint: disable=protected-access
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

    def _create_client(
        account_id: str, name: str, description: Optional[str] = None  # pylint: disable=unused-argument
    ) -> Mapping:
        nonlocal created_client_id

        created_client_id = str(uuid.uuid4())

        return {
            "client_id": created_client_id,
            "name": name,
            "description": description,
        }

    def _create_redirect(account_id: str, client_id: str, uri: str) -> Mapping:  # pylint: disable=unused-argument
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


def dummy_client_for_vpc_tests(cloud_with_vpc: Optional[str] = None) -> AivenCLI:
    cli = AivenCLI()

    class Client:  # pylint: disable=too-few-public-methods
        def list_project_vpcs(self, project: str) -> dict:  # pylint: disable=unused-argument
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
        cli._get_service_project_vpc_id()  # pylint: disable=protected-access
    assert str(excinfo.value).startswith("Cloud my-cloud has a VPC")


def test_cloud_has_vpc_user_said_nothing_and_no_cloud_switch() -> None:
    """When the user does not specify --cloud, we assume an "earlier" cloud will be re-used

    (and that the user is OK with the configuration of that cloud)
    """
    cli = dummy_client_for_vpc_tests("my-cloud")
    cli.parse_args(["service", "create", "--project=my-name", "--service-type=pg", "service-name"])
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
        cli._get_service_project_vpc_id()  # pylint: disable=protected-access
    assert str(excinfo.value).startswith("Only one of --project-vpc-id")


def test_cloud_has_no_vpc_user_said_nothing() -> None:
    cli = dummy_client_for_vpc_tests()
    cli.parse_args(["service", "create", "--project=my-name", "--cloud=my-cloud", "--service-type=pg", "service-name"])
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
    vpc_id = cli._get_service_project_vpc_id()  # pylint: disable=protected-access
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
        cli._get_service_project_vpc_id()  # pylint: disable=protected-access
    assert str(excinfo.value).startswith("Only one of --project-vpc-id")
