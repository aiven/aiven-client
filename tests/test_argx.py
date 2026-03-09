# Copyright 2020, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client import client as aiven_client
from aiven.client.argx import arg, CommandLineTool, UserError
from functools import cached_property
from typing import Callable, NoReturn
from unittest import mock

import io
import json


class TestCLI(CommandLineTool):
    __test__ = False  # to avoid PytestCollectionWarning

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
    cli.extend_commands(cli)  # Force the CLI to have its full arg set at execution

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


class TestPrintResponseAutoJson:
    """When stdout is not a TTY, print_response should emit JSON by default."""

    def _make_tool(self) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.no_auto_json = False
        tool.args.fields = None
        return tool

    def test_non_tty_emits_json(self) -> None:
        """When file is non-TTY and json=False, output should still be JSON."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        parsed = json.loads(output)
        assert parsed == [{"name": "svc1", "plan": "hobby"}]

    def test_tty_emits_table(self) -> None:
        """When file is a TTY and json=False, output should be a table."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        assert "name" in output.lower()
        assert not output.strip().startswith("[")

    def test_explicit_json_true_always_emits_json(self) -> None:
        """When json=True explicitly, always emit JSON regardless of TTY."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1"}],
            json=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1"}]

    def test_no_auto_json_flag_disables_detection(self) -> None:
        """--no-auto-json should preserve table output even in non-TTY."""
        tool = self._make_tool()
        tool.args.no_auto_json = True
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        assert not output.strip().startswith("[")

    def test_format_string_overrides_auto_json(self) -> None:
        """When --format is given, it takes priority over auto-JSON."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1"}],
            json=False,
            format="{name}",
            file=buf,
        )
        assert buf.getvalue().strip() == "svc1"


class TestStructuredErrorOutput:
    """In non-TTY contexts, errors should be emitted as JSON to stdout."""

    def _make_tool_that_raises(self, exception: Exception) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.config = "/dev/null"
        tool.args.no_auto_json = False
        tool.run_actual = mock.Mock(side_effect=exception)  # type: ignore[assignment]
        tool.parse_args = mock.Mock()  # type: ignore[assignment]
        return tool

    def _run_tool(self, tool: CommandLineTool, buf: io.StringIO) -> int | None:
        with mock.patch("sys.stdout", buf), mock.patch("aiven.client.argx.Config", return_value={}):
            return tool.run(args=["some", "command"])

    def test_user_error_json_on_non_tty(self) -> None:
        """UserError should produce JSON error on non-TTY stdout."""
        tool = self._make_tool_that_raises(UserError("project not found"))
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]

        exit_code = self._run_tool(tool, buf)

        assert exit_code == 1
        output = buf.getvalue()
        parsed = json.loads(output)
        assert parsed["error"] is True
        assert "project not found" in parsed["message"]
        assert parsed["exit_code"] == 1

    def test_user_error_plain_on_tty(self) -> None:
        """UserError should NOT produce JSON on TTY stdout (backward compat)."""
        tool = self._make_tool_that_raises(UserError("project not found"))
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]

        exit_code = self._run_tool(tool, buf)

        assert exit_code == 1
        assert buf.getvalue() == ""

    def test_client_error_includes_status(self) -> None:
        """client.Error should include HTTP status in JSON error."""
        http_forbidden = 403
        resp = mock.Mock()
        resp.text = '{"message": "forbidden"}'
        error = aiven_client.Error(resp, status=http_forbidden)
        tool = self._make_tool_that_raises(error)
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]

        exit_code = self._run_tool(tool, buf)

        assert exit_code == 1
        parsed = json.loads(buf.getvalue())
        assert parsed["error"] is True
        assert parsed["status"] == http_forbidden


class TestFieldsFiltering:
    """--fields should filter output to only requested keys."""

    def _make_tool(self, fields: str | None = None) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.no_auto_json = True
        tool.args.fields = fields
        return tool

    def test_fields_filters_json_output(self) -> None:
        tool = self._make_tool(fields="name,plan")
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby", "state": "RUNNING", "cloud": "aws"}],
            json=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1", "plan": "hobby"}]

    def test_fields_filters_table_output(self) -> None:
        tool = self._make_tool(fields="name,plan")
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby", "state": "RUNNING"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        assert "svc1" in output
        assert "RUNNING" not in output

    def test_no_fields_returns_all(self) -> None:
        tool = self._make_tool(fields=None)
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "state": "RUNNING"}],
            json=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1", "state": "RUNNING"}]

    def test_fields_single_item(self) -> None:
        tool = self._make_tool(fields="name")
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            {"name": "svc1", "plan": "hobby"},
            json=True,
            single_item=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert isinstance(parsed, dict)
        assert parsed == {"name": "svc1"}

    def test_single_item_json_emits_object_not_array(self) -> None:
        """single_item=True with json=True must emit {}, not [{}]."""
        tool = self._make_tool(fields=None)
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            {"name": "svc1", "plan": "hobby"},
            json=True,
            single_item=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        # Must be a dict, not a list
        assert isinstance(parsed, dict)
        assert parsed == {"name": "svc1", "plan": "hobby"}

    def test_single_item_json_with_fields_emits_object(self) -> None:
        """single_item=True + json=True + --fields must emit filtered {}."""
        tool = self._make_tool(fields="name")
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            {"name": "svc1", "plan": "hobby"},
            json=True,
            single_item=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert isinstance(parsed, dict)
        assert parsed == {"name": "svc1"}
