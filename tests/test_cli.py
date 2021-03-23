# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client.cli import AivenCLI
from collections import namedtuple

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
