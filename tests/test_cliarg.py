# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from _pytest.logging import LogCaptureFixture
from aiven.client.argx import CommandLineTool
from aiven.client.cliarg import arg


def test_user_config_json_error_json(caplog: LogCaptureFixture) -> None:
    """Test that @arg.user_config_json causes
    CommandLineTool.run() to exit cleanly with return value 1
    if JSON is incorrect
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config_json()
        @arg()
        def t(self) -> None:
            """t"""

    error_json_arg = ["t", "--user-config-json", "bar"]
    test_class = T("avn")
    ret = test_class.run(args=error_json_arg)
    # The message can vary across python versions
    assert (
        "Invalid user_config_json: Expecting value: line 1 column 1 (char 0)" in caplog.text
        or "Invalid user_config_json: Unexpected 'b': line 1 column 1 (char 0)" in caplog.text
    )
    assert ret == 1


def test_user_config_json_error_conflict() -> None:
    """Test that @arg.user_config_json causes
    CommandLineTool.run() to exit cleanly with return value 1
    if both user_config (-c) and --user-config-json parameters
    are given
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config
        @arg.user_config_json()
        @arg()
        def t(self) -> None:
            """t"""

    error_conflict_arg = ["t", "-c", "userconfkey=val", "--user-config-json", '{"foo":"bar"}']
    test_class = T("avn")
    ret = test_class.run(args=error_conflict_arg)
    assert ret == 1


def test_user_config_json_success() -> None:
    """Success scenario"""

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config_json()
        @arg()
        def t(self) -> None:
            """t"""

    valid_json_arg = ["t", "--user-config-json", '{"foo":"bar"}']
    test_class = T("avn")
    ret = test_class.run(args=valid_json_arg)
    assert ret is None  # Should run() return 0 actually?
    assert test_class.args.user_config_json == {"foo": "bar"}


def test_user_config_success() -> None:
    """Test that user config parameter -c works and not cause conflict with
    --user_config_json
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config
        @arg.user_config_json()
        @arg()
        def t(self) -> None:
            """t"""

    user_config_arg = ["t", "-c", "userconfkey=val"]
    test_class = T("avn")
    ret = test_class.run(args=user_config_arg)
    assert ret is None
