# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from aiven.client import envdefault, pretty
from typing import Optional

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
    import argcomplete  # pylint: disable=import-error

    ARGCOMPLETE_INSTALLED = True
except ImportError:
    ARGCOMPLETE_INSTALLED = False

try:
    from .version import __version__  # pylint: disable=no-name-in-module
except ImportError:
    __version__ = "UNKNOWN"

# cached_property only exists since python 3.8
SKIP_EVALUATION_TYPES = (property, )
if hasattr(functools, "cached_property"):
    SKIP_EVALUATION_TYPES += (functools.cached_property, )

ARG_LIST_PROP = "_arg_list"
LOG_FORMAT = "%(levelname)s\t%(message)s"


class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter to display the default value only for integers and non-empty strings"""

    def _get_help_string(self, action):
        help_text = action.help
        if "%(default)" not in action.help and action.default is not argparse.SUPPRESS:
            if action.option_strings or action.nargs in [
                argparse.OPTIONAL,
                argparse.ZERO_OR_MORE,
            ]:
                if (not isinstance(action.default, bool)
                    and isinstance(action.default, int)) or (isinstance(action.default, str) and action.default):
                    help_text += " (default: %(default)s)"
        return help_text


class UserError(Exception):
    """User error"""


def arg(*args, **kwargs):
    """ Declares an argument of an CLI command.

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

    def wrap(func):
        arg_list = getattr(func, ARG_LIST_PROP, None)
        if arg_list is None:
            arg_list = []
            setattr(func, ARG_LIST_PROP, arg_list)

        if args or kwargs:
            arg_list.insert(0, (args, kwargs))

        return func

    return wrap


class Config(dict):
    def __init__(self, file_path):
        dict.__init__(self)
        self.file_path = file_path
        self.load()

    def load(self):
        self.clear()
        try:
            with open(self.file_path) as fp:
                self.update(jsonlib.load(fp))
        except IOError as ex:
            if ex.errno == errno.ENOENT:
                return

            raise UserError(
                "Failed to load configuration file {!r}: {}: {}".format(self.file_path, ex.__class__.__name__, ex)
            ) from ex
        except ValueError as ex:
            raise UserError("Invalid JSON in configuration file {!r}".format(self.file_path)) from ex

    def save(self):
        config_dir = os.path.dirname(self.file_path)
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir)
            os.chmod(config_dir, 0o700)

        with open(self.file_path, "w") as fp:
            os.chmod(fp.name, 0o600)
            jsonlib.dump(self, fp, sort_keys=True, indent=4)


class CommandLineTool:  # pylint: disable=old-style-class
    def __init__(self, name, parser: Optional[argparse.ArgumentParser] = None):
        self.log = logging.getLogger(name)
        self.config = None
        self._cats = {}
        self._extensions = []
        self.parser = parser or argparse.ArgumentParser(prog=name, formatter_class=CustomFormatter)
        self.parser.add_argument(
            "--config",
            help="config file location %(default)r",
            default=envdefault.AIVEN_CLIENT_CONFIG,
        )
        self.parser.add_argument("--version", action="version", version="aiven-client {}".format(__version__))
        self.subparsers = self.parser.add_subparsers(title="command categories", dest="command", help="", metavar="")
        self.args = None

    def add_cmd(self, func):
        """Add a parser for a single command method call"""
        assert func.__doc__, f"Missing docstring for {func.__qualname__}"

        # allow multi-level commands, separating each level with double underscores
        if "__" in func.__name__:
            cmd_parts = func.__name__.split("__")
        else:
            # previously we only allowed two levels, separated by a single underscore
            cmd_parts = func.__name__.split("_", 1)

        cmd_parts = [part.replace("_", "-") for part in cmd_parts]
        cats, cmd = cmd_parts, cmd_parts.pop()

        subparsers = self.subparsers
        for level in range(len(cats)):
            cat = tuple(cats[:level + 1])
            if cat not in self._cats:
                parser = subparsers.add_parser(
                    cat[-1],
                    help=" ".join(cat).title() + " commands",
                    formatter_class=CustomFormatter,
                )
                self._cats[cat] = parser.add_subparsers()
            subparsers = self._cats[cat]

        parser = subparsers.add_parser(cmd, help=func.__doc__, formatter_class=CustomFormatter)
        parser.set_defaults(func=func)

        for arg_prop in getattr(func, ARG_LIST_PROP, []):
            parser.add_argument(*arg_prop[0], **arg_prop[1])

        # Ensure the list of actions remains sorted as we append to to it.
        self.subparsers._choices_actions.sort(key=lambda item: item.dest)  # pylint: disable=protected-access

    def add_args(self, parser):
        pass  # override in sub-class

    def extend_commands(self, sub_client):
        """Add top-level args and all commands from a CommandLineTool instance"""
        sub_client.add_args(self.parser)  # top-level args
        sub_client.add_cmds(self.add_cmd)  # sub-commands
        self._extensions.append(sub_client)

    def add_cmds(self, add_func):
        """Add every method tagged with @arg as a command"""
        for prop in dir(self):
            # Skip @property and @cached_property attributes to delay coercing their evaluation.
            classprop = getattr(self.__class__, prop, None)
            if isinstance(classprop, SKIP_EVALUATION_TYPES):
                continue
            func = getattr(self, prop, None)
            if getattr(func, ARG_LIST_PROP, None) is not None:
                add_func(func)

    def parse_args(self, args=None):
        self.extend_commands(self)

        if ARGCOMPLETE_INSTALLED:
            argcomplete.autocomplete(self.parser)

        args = self.parser.parse_args(args=args)
        for ext in self._extensions:
            ext.args = args

    def pre_run(self, func):
        """Override in sub-class"""

    def expected_errors(self):
        return []

    def print_response(
        self,
        result,
        json=True,
        format=None,  # pylint: disable=redefined-builtin
        drop_fields=None,
        table_layout=None,
        single_item=False,
        header=True,
        csv=False,
        file=None,
    ):  # pylint: disable=redefined-builtin
        """print request response in chosen format"""
        if file is None:
            file = sys.stdout

        if format is not None:
            if single_item:
                result = [result]
            for item in result:
                print(format.format(**item), file=file)
        elif json:
            print(
                jsonlib.dumps(result, indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder),
                file=file,
            )
        elif csv:
            fields = []
            for field in table_layout:
                if isinstance(field, str):
                    fields.append(field)
                else:
                    fields.extend(field)

            writer = csvlib.DictWriter(file, extrasaction="ignore", fieldnames=fields)
            if header:
                writer.writeheader()
            if single_item:
                result = [result]
            for item in result:
                writer.writerow(item)
        else:
            if single_item:
                result = [result]

            pretty.print_table(
                result,
                drop_fields=drop_fields,
                table_layout=table_layout,
                header=header,
                file=file,
            )

    def run(self, args=None):
        args = args or sys.argv[1:]
        if not args:
            args = ["--help"]

        self.parse_args(args=args)
        self.config = Config(self.args.config)
        expected_errors = [
            requests.exceptions.ConnectionError,
            UserError,
            aiven.client.client.Error,
        ]
        for ext in self._extensions:  # note: _extensions includes self
            expected_errors.extend(ext.expected_errors())
            ext.config = self.config
        try:
            return self.run_actual(args)
        except tuple(expected_errors) as ex:  # pylint: disable=catching-non-exception
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

    def run_actual(self, args_for_help):
        func = getattr(self.args, "func", None)
        if not func:
            self.parser.parse_args(args_for_help + ["--help"])
            return 1

        self.pre_run(func)
        return func()  # pylint: disable=not-callable

    def main(self, args=None):
        # TODO: configurable log level
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
        logging.getLogger("requests").setLevel(logging.WARNING)
        sys.exit(self.run(args))
