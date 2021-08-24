# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

# pylint: disable=no-member
from aiven.client.argx import CommandLineTool
from aiven.client.cliarg import arg


def test_user_config_json_error_json():
    """Test that @arg.user_config_json causes
    CommandLineTool.run() to exit cleanly with return value 1
    if JSON is incorrect
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config_json()
        @arg()
        def t(self):
            """t"""

    error_json_arg = ["t", "--user-config-json", "foo"]
    test_class = T("avn")
    ret = test_class.run(args=error_json_arg)
    assert ret == 1


def test_user_config_json_error_conflict():
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
        def t(self):
            """t"""

    error_conflict_arg = ["t", "-c", "userconfkey=val", "--user-config-json", '{"foo":"bar"}']
    test_class = T("avn")
    ret = test_class.run(args=error_conflict_arg)
    assert ret == 1


def test_user_config_json_success():
    """Success scenario
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config_json()
        @arg()
        def t(self):
            """t"""

    valid_json_arg = ["t", "--user-config-json", '{"foo":"bar"}']
    test_class = T("avn")
    ret = test_class.run(args=valid_json_arg)
    assert ret is None  # Should run() return 0 actually?
    assert test_class.args.user_config_json == {"foo": "bar"}


def test_user_config_success():
    """Test that user config parameter -c works and not cause conflict with
    --user_config_json
    """

    class T(CommandLineTool):
        """Test class"""

        @arg.user_config
        @arg.user_config_json()
        @arg()
        def t(self):
            """t"""

    user_config_arg = ["t", "-c", "userconfkey=val"]
    test_class = T("avn")
    ret = test_class.run(args=user_config_arg)
    assert ret is None
