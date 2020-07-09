# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from aiven.client import envdefault, pretty
from collections.abc import Mapping, Sequence

import aiven.client.client
import argparse
import csv as csvlib
import enum
import errno
import json as jsonlib
import logging
import os
import requests.exceptions
import ruamel.yaml as yamllib
import sys

try:
    basestring
except NameError:
    basestring = str  # pylint: disable=redefined-builtin

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
            )
        except ValueError:
            raise UserError("Invalid JSON in configuration file {!r}".format(self.file_path))

    def save(self):
        config_dir = os.path.dirname(self.file_path)
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir)
            os.chmod(config_dir, 0o700)

        with open(self.file_path, "w") as fp:
            os.chmod(fp.name, 0o600)
            jsonlib.dump(self, fp, sort_keys=True, indent=4)


class OutputFormats(enum.Enum):
    """Defines the supported output formats on the command line."""
    TABLE = "table"
    TABLE_NOHEADER = "table-noheader"
    CSV = "csv"
    CSV_NOHEADER = "csv-noheader"
    JSON = "json"
    JSON_COMPACT = "json-compact"
    YAML = "yaml"

    def __str__(self):
        return str(self.value)


class CommandLineTool:  # pylint: disable=old-style-class,too-many-instance-attributes
    def __init__(self, name):
        self.log = logging.getLogger(name)
        self.config = None
        self._cats = {}
        self._extensions = []

        if name is None:
            raise ValueError("name cannot be None")

        if not isinstance(name, basestring):
            raise ValueError("name must be a string")

        self._output_format = OutputFormats.TABLE  # type: OutputFormats
        self._output_stream = sys.stdout
        self._single_item = False

        # Early parser handles things like logging which need to be setup as early as possible.
        # Output from early parser is never shown.
        self.early_parser = argparse.ArgumentParser(
            prog=name, formatter_class=CustomFormatter, add_help=False
        )  # Important - help goes to real parser
        self.early_parser.add_argument(
            "--log-level",
            choices=list(logging._nameToLevel),  # pylint: disable=protected-access
            default=logging._levelToName[logging.INFO],
            help="Log level"
        )
        self.early_parser.add_argument(
            "--request-log-level",
            choices=list(logging._nameToLevel),
            default=logging._levelToName[logging.WARNING],
            help="HTTP request log level"
        )
        self.early_parser.add_argument(
            "--output-format",
            type=OutputFormats,
            choices=list(OutputFormats),
            default=self._output_format,
            help="Output format"
        )
        self.early_parser.add_argument("--output", type=str, default="-", help="Output destination")

        self.early_parser.add_argument(
            "--config", help="config file location %(default)r", default=envdefault.AIVEN_CLIENT_CONFIG
        )

        # Parser is the actual command line parser which displays to the user.
        self.parser = argparse.ArgumentParser(prog=name, formatter_class=CustomFormatter)
        self.parser.add_argument('--version', action='version', version='aiven-client {}'.format(__version__))

        # Add the early parser options to the real parser so they'll appear in the help we show the
        # user.
        for action in self.early_parser._actions:
            self.parser._add_action(action)

        self.subparsers = self.parser.add_subparsers(title="command categories", dest="command", help="", metavar="")
        self.args = None

    def add_cmd(self, func):
        """Add a parser for a single command method call"""
        assert func.__doc__, func

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

    def add_args(self, parser):
        """This method should be overriden in subclasses to add group arguments."""

    def add_cmds(self, add_func):
        """Add every method tagged with @arg as a command"""
        for prop in dir(self):
            # Skip @properties to avoid evaluating them
            classprop = getattr(self.__class__, prop, None)
            if isinstance(classprop, property):
                continue
            func = getattr(self, prop, None)
            if getattr(func, ARG_LIST_PROP, None) is not None:
                add_func(func)

    def extend_commands(self, sub_client):
        """Add top-level args and all commands from a CommandLineTool instance"""
        sub_client.add_args(self.parser)  # top-level args
        sub_client.add_cmds(self.add_cmd)  # sub-commands
        self._extensions.append(sub_client)

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
        json=False,
        format=None,  # pylint: disable=redefined-builtin
        drop_fields=None,
        table_layout=None,
        single_item=False,
        header=True,
        csv=False,
        file=None,
    ):  # pylint: disable=redefined-builtin
        """print request response in chosen format"""

        # Deprecation compatibility: map the old keyword args into the new enum:
        output_stream = self._output_stream if file is None else file

        output_format = self._output_format

        if json is True:
            output_format = OutputFormats.JSON
        elif csv is True:
            output_format = OutputFormats.CSV if header is True else OutputFormats.CSV_NOHEADER

        # Detect when a single item has been passed and reframe it as a list.
        if single_item is True or not isinstance(result, Sequence) or isinstance(result, str):
            result = [result]

        if format is not None:
            prepared_data = pretty.prepare_table(result, table_layout)
            # This code supports the format arg exactly as currently used.
            if not isinstance(result, (Mapping, Sequence)) or isinstance(result, basestring):
                raise NotImplementedError(
                    "Cannot output with format non-mapping or sequence types types: got {result_type}".format(
                        result_type=type(result)
                    )
                )
            for table_row in prepared_data.table_rows:
                output_stream.write(format.format(**table_row))
                output_stream.write("\n")

        if output_format in (OutputFormats.TABLE, OutputFormats.TABLE_NOHEADER):
            pretty.print_table(
                result,
                drop_fields=drop_fields,
                table_layout=table_layout,
                header=output_format == OutputFormats.TABLE,
                file=output_stream
            )

        elif output_format in (OutputFormats.CSV, OutputFormats.CSV_NOHEADER):
            prepared_data = pretty.prepare_table(result, table_layout)
            fields = []
            if len(prepared_data.vertical_fields) != 0:
                fields.append("")

            writer = csvlib.DictWriter(output_stream, extrasaction="ignore", fieldnames=fields)

            if output_format == OutputFormats.CSV:
                writer.writeheader()

            for row in prepared_data.table_rows:
                row_item = {k: pretty.format_item(v) for k, v in row.items()}
                row_item[""] = "\n".join(pretty.yield_vertical_fields(row_item, prepared_data.vertical_fields))
                writer.writerow(row_item)

        elif output_format == OutputFormats.JSON:
            jsonlib.dump(result, output_stream, indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder)
            output_stream.write("\n")
        elif output_format == OutputFormats.JSON_COMPACT:
            jsonlib.dump(result, output_stream, sort_keys=True, cls=pretty.CustomJsonEncoder)
            output_stream.write("\n")
        elif output_format == OutputFormats.YAML:
            yamllib.round_trip_dump(result, output_stream, default_flow_style=False)

        else:
            raise ValueError("unrecognized output format: {output_format}".format(output_format=output_format.value))

    def run(self, args=None):
        args = args or sys.argv[1:]
        if not args:
            args = ["--help"]

        # Parse the early arguments
        early_args, _ = self.early_parser.parse_known_args(args)

        # Configure log levels early
        logging.basicConfig(
            level=logging._nameToLevel[early_args.log_level],  # pylint: disable=protected-access
            format=LOG_FORMAT
        )
        logging.getLogger("requests").setLevel(
            logging._nameToLevel[early_args.request_log_level]  # pylint: disable=protected-access
        )

        self.config = Config(early_args.config)

        self._output_format = early_args.output_format

        if early_args.output == "-" or early_args.output == "":
            self._output_stream = sys.stdout
        else:
            self._output_stream = open(early_args.output, "wb")

        # Parse the other arguments (in practice parses them again - this catches errors in the early_args)
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

    def main(self):
        sys.exit(self.run())
