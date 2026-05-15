# Copyright 2020, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.argx import arg, CommandLineTool
from collections.abc import Callable
from functools import cached_property
from typing import NoReturn


class TestCLI(CommandLineTool):
    __test__ = False

    @arg()
    def xxx(self) -> None:
        """7"""

    @arg()
    def aaa(self) -> None:
        """1"""

    @arg()
    def ccc(self) -> None:
        """4"""


class SubCLI(CommandLineTool):
    @arg()
    def yyy(self) -> None:
        """8"""

    @arg()
    def bbb(self) -> None:
        """2

        With more explaining
        """

    @arg()
    def ddd(self) -> None:
        """5"""


class SubCLI2(CommandLineTool):
    @arg()
    def yyz(self) -> None:
        """9"""

    @arg()
    def bbc(self) -> None:
        """3"""

    @arg()
    def dde(self) -> None:
        """6"""


def test_extended_commands_remain_alphabetically_ordered() -> None:
    cli = TestCLI("testcli")
    cli.extend_commands(cli)

    sl2 = SubCLI2("subcli2")
    sl = SubCLI("subcli")

    cli.extend_commands(sl2)
    cli.extend_commands(sl)

    action_order = [item.dest for item in cli.subparsers._choices_actions]
    assert action_order == ["aaa", "bbb", "bbc", "ccc", "ddd", "dde", "xxx", "yyy", "yyz"]


def test_extended_command_has_function_help() -> None:
    cli = TestCLI("testcli")
    cli.extend_commands(cli)  # Force the CLI to have its full arg set at execution

    sl = SubCLI("subcli")

    cli.extend_commands(sl)

    help_text = cli.subparsers.choices[sl.bbb.__name__].format_help()
    assert sl.bbb.__doc__ is not None
    assert sl.bbb.__doc__ in help_text


class DescriptorCLI(CommandLineTool):
    @property
    def raise1(self) -> NoReturn:
        raise RuntimeError("evaluated raise1")

    if cached_property is not None:

        @cached_property
        def raise2(self) -> NoReturn:
            raise RuntimeError("evaluated raise2")

    @arg("something")
    def example_command(self) -> None:
        """Example command."""


def test_descriptors_are_not_eagerly_evaluated() -> None:
    cli = DescriptorCLI("DescriptorCLI")
    calls: list[Callable] = []
    cli.add_cmds(calls.append)
    assert calls == [cli.example_command]


def test_help_text_escapes_literal_percent() -> None:
    """Test that literal % in help text is escaped for Python 3.14 compatibility."""

    class PercentCLI(CommandLineTool):
        @arg("--threshold", type=float, default=0.75, help="Shows 100% of the data")
        def command_with_percent(self) -> None:
            """Command with % in help."""

    cli = PercentCLI("percentcli")
    cli.extend_commands(cli)

    # Get the help formatter's output for the argument
    parser = cli.subparsers.choices["command-with-percent"]

    # Find the --threshold action
    threshold_action = None
    for action in parser._actions:
        if "--threshold" in action.option_strings:
            threshold_action = action
            break

    assert threshold_action is not None

    # The formatter should escape % to %%
    formatted_help = parser._get_formatter()._get_help_string(threshold_action)
    assert formatted_help is not None

    # Should contain escaped %% and automatic default
    assert "100%%" in formatted_help
    assert "(default: %(default)s)" in formatted_help


def test_help_text_preserves_default_format_codes() -> None:
    """Test that user-provided %(default) format codes are not escaped."""

    class FormatCLI(CommandLineTool):
        @arg("--url", help="Server URL (default: %(default)r)")
        def command_with_format(self) -> None:
            """Command with format code."""

    cli = FormatCLI("formatcli")
    cli.extend_commands(cli)

    parser = cli.subparsers.choices["command-with-format"]

    url_action = None
    for action in parser._actions:
        if "--url" in action.option_strings:
            url_action = action
            break

    assert url_action is not None

    formatted_help = parser._get_formatter()._get_help_string(url_action)
    assert formatted_help is not None

    # Should preserve user's format code, not escape it
    assert "%(default)r" in formatted_help
    # Should NOT add automatic default since user already has one
    assert formatted_help.count("%(default)") == 1


def test_help_text_adds_automatic_default_for_int() -> None:
    """Test that automatic (default: X) is added for integer defaults."""

    class DefaultCLI(CommandLineTool):
        @arg("--count", type=int, default=5, help="Number of items")
        def command_with_int_default(self) -> None:
            """Command with int default."""

    cli = DefaultCLI("defaultcli")
    cli.extend_commands(cli)

    parser = cli.subparsers.choices["command-with-int-default"]

    count_action = None
    for action in parser._actions:
        if "--count" in action.option_strings:
            count_action = action
            break

    assert count_action is not None

    formatted_help = parser._get_formatter()._get_help_string(count_action)
    assert formatted_help is not None

    # Should have automatic default added
    assert "(default: %(default)s)" in formatted_help
    assert formatted_help == "Number of items (default: %(default)s)"


def test_help_text_adds_automatic_default_for_string() -> None:
    """Test that automatic (default: X) is added for non-empty string defaults."""

    class StringDefaultCLI(CommandLineTool):
        @arg("--name", default="test", help="Item name")
        def command_with_string_default(self) -> None:
            """Command with string default."""

    cli = StringDefaultCLI("stringdefaultcli")
    cli.extend_commands(cli)

    print(cli.subparsers)
    print(cli.subparsers.choices)
    parser = cli.subparsers.choices["command-with-string-default"]

    name_action = None
    for action in parser._actions:
        if "--name" in action.option_strings:
            name_action = action
            break

    assert name_action is not None

    formatted_help = parser._get_formatter()._get_help_string(name_action)
    assert formatted_help is not None

    # Should have automatic default added
    assert "(default: %(default)s)" in formatted_help


def test_help_text_no_default_for_bool() -> None:
    """Test that automatic default is NOT added for boolean (store_true/store_false)."""

    class BoolCLI(CommandLineTool):
        @arg("--verbose", action="store_true", help="Enable verbose output")
        def command_with_bool(self) -> None:
            """Command with bool flag."""

    cli = BoolCLI("boolcli")
    cli.extend_commands(cli)

    parser = cli.subparsers.choices["command-with-bool"]

    verbose_action = None
    for action in parser._actions:
        if "--verbose" in action.option_strings:
            verbose_action = action
            break

    assert verbose_action is not None

    formatted_help = parser._get_formatter()._get_help_string(verbose_action)
    assert formatted_help is not None

    # Should NOT have automatic default for boolean
    assert "(default:" not in formatted_help
    assert formatted_help == "Enable verbose output"
