# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from .pretty import TableLayout
from aiven.client import envdefault, pretty
from argparse import Action, ArgumentParser, Namespace
from os import PathLike
from typing import Any, Callable, cast, Collection, Mapping, NoReturn, Sequence, TextIO, TYPE_CHECKING, TypeVar

import aiven.client.client
import argparse
import csv as csvlib
import errno
import functools
import json as jsonlib
import logging
import os
import requests.exceptions
import sys

# Optional shell completions
try:
    import argcomplete  # type: ignore

    ARGCOMPLETE_INSTALLED = True
except ImportError:
    ARGCOMPLETE_INSTALLED = False

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

SKIP_EVALUATION_TYPES = (property, functools.cached_property)
ARG_LIST_PROP = "_arg_list"
LOG_FORMAT = "%(levelname)s\t%(message)s"


class ArgumentDeprecationNotice(argparse.Action):
    """Base class for creating deprecation notice for the arguments of avn CLI."""

    log = logging.getLogger("deprecation-notice")
    help_prefix = "(DEPRECATED)"
    message = "Argument is deprecated: '%s'."

    message_hint: str | None = None
    help_hint: str | None = None
    ignore_argument: bool = False
    log_level = logging.WARNING

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        for k, v in kwargs.copy().items():
            if k.startswith("deprecation_"):
                setattr(self, "_".join(k.split("_")[1:]), v)
                kwargs.pop(k)

        super().__init__(*args, **kwargs)

    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        # default action is store
        setattr(namespace, self.dest, values)

        if values is not None:
            msg = f"{self.message if self.message else ''}{' ' + self.message_hint if self.message_hint else ''}"
            self.log.log(self.log_level, msg, ",".join(self.option_strings))

        if self.ignore_argument:
            delattr(namespace, self.dest)


class NextReleaseDeprecationNotice(ArgumentDeprecationNotice):
    message = "Argument `%s` is deprecated and will be removed in the next release."


class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter to display the default value only for integers and non-empty strings"""

    def _get_help_string(self, action: Action) -> str:
        help_text = action.help or ""
        if "%(default)" not in help_text and action.default is not argparse.SUPPRESS:
            if action.option_strings or action.nargs in [
                argparse.OPTIONAL,
                argparse.ZERO_OR_MORE,
            ]:
                if (not isinstance(action.default, bool) and isinstance(action.default, int)) or (
                    isinstance(action.default, str) and action.default
                ):
                    help_text += " (default: %(default)s)"

        if isinstance(action, ArgumentDeprecationNotice):
            help_text = (
                f"{action.help_prefix + ' ' if action.help_prefix else ''}"
                f"{help_text}"
                f"{'. ' + action.help_hint if action.help_hint else ''}"
            )

        return help_text


class UserError(Exception):
    """User error"""


F = TypeVar("F", bound=Callable)


class Arg:
    """Declares an argument of an CLI command.

    This decorator accepts the same arguments as `argparse.Parser::add_argument`.

    Methods marked with this decorator will be exposed as a CLI command, the
    argument is made available through the instance attribute `self.args`.
    `args` is an `argparse.Namespace` instance.

    Example usage::

        class CLI(CommandLineTool):

            @arg("n", type=int)
            def command(self):
                print(self.args.n)
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        def wrap(func: F) -> F:
            arg_list = getattr(func, ARG_LIST_PROP, None)
            if arg_list is None:
                arg_list = []
                setattr(func, ARG_LIST_PROP, arg_list)

            if args or kwargs:
                arg_list.insert(0, (args, kwargs))

            return func

        return wrap

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Callable:
            ...

        def __setattr__(self, name: str, value: Callable) -> None:
            ...


arg = Arg()


def name_to_cmd_parts(name: str) -> list[str]:
    if "__" in name:
        # allow multi-level commands, separating each level with double underscores
        cmd_parts = name.split("__")
    else:
        # previously we only allowed two levels, separated by a single underscore
        cmd_parts = name.split("_", 1)

    return [part.replace("_", "-") for part in cmd_parts]


class Config(dict):
    def __init__(self, file_path: PathLike):
        dict.__init__(self)
        self.file_path = file_path
        self.load()

    def load(self) -> None:
        self.clear()
        try:
            with open(self.file_path, encoding="utf-8") as fp:
                self.update(jsonlib.load(fp))
        except OSError as ex:
            if ex.errno == errno.ENOENT:
                return

            raise UserError(
                "Failed to load configuration file {!r}: {}: {}".format(self.file_path, ex.__class__.__name__, ex)
            ) from ex
        except ValueError as ex:
            raise UserError("Invalid JSON in configuration file {!r}".format(self.file_path)) from ex

    def save(self) -> None:
        config_dir = os.path.dirname(self.file_path)
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir)
            os.chmod(config_dir, 0o700)

        with open(self.file_path, "w", encoding="utf-8") as fp:
            os.chmod(fp.name, 0o600)
            jsonlib.dump(self, fp, sort_keys=True, indent=4)


class CommandLineTool:
    config: Config

    def __init__(self, name: str, parser: argparse.ArgumentParser | None = None):
        self.log = logging.getLogger(name)
        self._cats: dict[tuple[str, ...], argparse._SubParsersAction] = {}
        self._extensions: list[CommandLineTool] = []
        self.parser = parser or argparse.ArgumentParser(prog=name, formatter_class=CustomFormatter)
        self.parser.add_argument(
            "--config",
            help="config file location %(default)r",
            default=envdefault.AIVEN_CLIENT_CONFIG,
        )
        self.parser.add_argument("--version", action="version", version="aiven-client {}".format(__version__))
        self.subparsers = self.parser.add_subparsers(title="command categories", dest="command", help="", metavar="")
        self.args: Namespace = Namespace()

    def add_cmd(self, func: Callable) -> None:
        """Add a parser for a single command method call"""
        assert func.__doc__, f"Missing docstring for {func.__qualname__}"

        cmd_parts = name_to_cmd_parts(func.__name__)
        cats, cmd = cmd_parts, cmd_parts.pop()

        subparsers = self.subparsers
        for level in range(len(cats)):
            cat = tuple(cats[: level + 1])
            if cat not in self._cats:
                parser = subparsers.add_parser(
                    cat[-1],
                    help=" ".join(cat).title() + " commands",
                    formatter_class=CustomFormatter,
                )
                self._cats[cat] = parser.add_subparsers()
            subparsers = self._cats[cat]

        parser = subparsers.add_parser(cmd, help=func.__doc__, description=func.__doc__, formatter_class=CustomFormatter)
        parser.set_defaults(func=func)

        for arg_prop in getattr(func, ARG_LIST_PROP, []):
            parser.add_argument(*arg_prop[0], **arg_prop[1])

        # Ensure the list of actions remains sorted as we append to to it.
        self.subparsers._choices_actions.sort(key=lambda item: item.dest)

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        pass  # override in sub-class

    def extend_commands(self, sub_client: CommandLineTool) -> None:
        """Add top-level args and all commands from a CommandLineTool instance"""
        sub_client.add_args(self.parser)  # top-level args
        sub_client.add_cmds(self.add_cmd)  # sub-commands
        self._extensions.append(sub_client)

    def add_cmds(self, add_func: Callable[[Callable], None]) -> None:
        """Add every method tagged with @arg as a command"""
        for prop in dir(self):
            # Skip @property and @cached_property attributes to delay coercing their evaluation.
            classprop = getattr(self.__class__, prop, None)
            if isinstance(classprop, SKIP_EVALUATION_TYPES):
                continue
            func = getattr(self, prop, None)
            if getattr(func, ARG_LIST_PROP, None) is not None:
                assert callable(func)
                add_func(func)

    def parse_args(self, args: Sequence[str] | None = None) -> None:
        self.extend_commands(self)

        if ARGCOMPLETE_INSTALLED:
            argcomplete.autocomplete(self.parser)

        ext_args = self.parser.parse_args(args=args)
        for ext in self._extensions:
            ext.args = ext_args

    def pre_run(self, func: Callable) -> None:
        """Override in sub-class"""

    def expected_errors(self) -> Sequence[type[BaseException]]:
        return []

    def _to_mapping_collection(
        self, obj: Mapping[str, Any] | Collection[Mapping[str, Any]], single_item: bool = False
    ) -> Collection[Mapping[str, Any]]:
        if single_item:
            assert isinstance(obj, Mapping)
            return [obj]
        else:
            assert isinstance(obj, Collection)
            return cast(Collection[Mapping[str, Any]], obj)

    def print_response(
        self,
        result: Mapping[str, Any] | Collection[Mapping[str, Any]],
        json: bool = True,
        format: str | None = None,
        drop_fields: Collection[str] | None = None,
        table_layout: TableLayout | None = None,
        single_item: bool = False,
        header: bool = True,
        csv: bool = False,
        file: TextIO | None = None,
    ) -> None:
        """print request response in chosen format"""
        if file is None:
            file = sys.stdout

        if format is not None:
            for item in self._to_mapping_collection(result, single_item=single_item):
                print(format.format(**item), file=file)
        elif json:
            assert isinstance(result, (Collection, Mapping))
            print(
                jsonlib.dumps(result, indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder),
                file=file,
            )
        elif csv:
            fields = []
            assert table_layout is not None
            for field in table_layout:
                if isinstance(field, str):
                    fields.append(field)
                else:
                    fields.extend(field)

            writer = csvlib.DictWriter(file, extrasaction="ignore", fieldnames=fields)
            if header:
                writer.writeheader()
            for item in self._to_mapping_collection(result, single_item=single_item):
                writer.writerow(item)
        else:
            pretty.print_table(
                self._to_mapping_collection(result, single_item=single_item),
                drop_fields=drop_fields,
                table_layout=table_layout,
                header=header,
                file=file,
            )

    def run(self, args: Sequence[str] | None = None) -> int | None:
        args = args or sys.argv[1:]
        if not args:
            args = ["--help"]

        self.parse_args(args=args)
        assert self.args is not None and hasattr(self.args, "config")
        self.config = Config(self.args.config)
        expected_errors: list[type[BaseException]] = [
            requests.exceptions.ConnectionError,
            UserError,
            aiven.client.client.Error,
        ]
        for ext in self._extensions:  # note: _extensions includes self
            expected_errors.extend(ext.expected_errors())
            ext.config = self.config
        try:
            return self.run_actual(args)
        except tuple(expected_errors) as ex:
            # nicer output on "expected" errors
            err = "command failed: {0.__class__.__name__}: {0}".format(ex)
            self.log.error(err)
            return 1
        except OSError as ex:
            if ex.errno != errno.EPIPE:
                raise
            self.log.error("*** output truncated ***")
            return 13  # SIGPIPE value in case anyone cares
        except KeyboardInterrupt:
            self.log.error("*** terminated by keyboard ***")
            return 2  # SIGINT

    def run_actual(self, args_for_help: Sequence[str]) -> int | None:
        func = getattr(self.args, "func", None)
        if not func:
            self.parser.parse_args(list(args_for_help) + ["--help"])
            return 1

        self.pre_run(func)
        return func()

    def main(self, args: Sequence[str] | None = None) -> NoReturn:
        # TODO: configurable log level
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
        logging.getLogger("requests").setLevel(logging.WARNING)
        sys.exit(self.run(args))
