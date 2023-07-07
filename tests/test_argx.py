# Copyright 2020, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.argx import arg, CommandLineTool
from functools import cached_property
from typing import Callable, NoReturn


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
