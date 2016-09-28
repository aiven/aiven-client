# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client.cli import AivenCLI
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
