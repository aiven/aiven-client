# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""Pretty-print JSON objects and lists as tables"""
from __future__ import annotations

from typing import Any, cast, Collection, Iterator, List, Mapping, TextIO, Tuple, Union

import datetime
import decimal
import fnmatch
import ipaddress
import itertools
import json
import sys

ResultType = Collection[Mapping[str, Any]]
TableLayout = Collection[Union[List[str], Tuple[str], str]]


class CustomJsonEncoder(json.JSONEncoder):
    def default(self, o: Any) -> str:
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        if isinstance(o, datetime.timedelta):
            return str(o)
        if isinstance(o, decimal.Decimal):
            return str(o)
        if isinstance(
            o,
            (
                ipaddress.IPv4Address,
                ipaddress.IPv6Address,
                ipaddress.IPv4Network,
                ipaddress.IPv6Network,
                ipaddress.IPv4Interface,
                ipaddress.IPv6Interface,
            ),
        ):
            return o.compressed

        return json.JSONEncoder.default(self, o)


def format_item(key: str | None, value: Any) -> str:
    if isinstance(value, list):
        formatted = ", ".join(format_item(None, entry) for entry in value)
    elif isinstance(value, dict):
        formatted = json.dumps(value, sort_keys=True, cls=CustomJsonEncoder)
    elif isinstance(value, str):
        if key and key.endswith("_time") and value.endswith("Z") and "." in value:
            # drop microseconds from timestamps
            value = value.split(".", 1)[0] + "Z"
        # json encode strings, but if the input string is exactly the same
        # as the output without quotes we'll go with the original
        json_v = json.dumps(value)
        quoted_v = '"{}"'.format(value)
        if json_v == quoted_v or json_v.replace("\\u00a3", "£").replace("\\u20ac", "€") == quoted_v:
            formatted = value
        else:
            formatted = json_v
    elif isinstance(value, datetime.datetime):
        formatted = value.isoformat()
    elif isinstance(value, datetime.timedelta):
        formatted = str(value)
    else:
        # again, if adding quotes is only thing json econding would do, omit them
        json_v = json.dumps(value, sort_keys=True, cls=CustomJsonEncoder)
        quoted_v = '"{}"'.format(value)
        if json_v == quoted_v:
            formatted = "{}".format(value)
        else:
            formatted = json_v

    return formatted


def flatten_list(complex_list: TableLayout | None) -> Collection[str]:
    """Flatten a multi-dimensional list to 1D list"""
    if complex_list is None:
        return []
    flattened_list: list[str] = []
    for level1 in complex_list:
        if isinstance(level1, (list, tuple)):
            flattened_list.extend(flatten_list(level1))
        else:
            flattened_list.append(level1)
    return flattened_list


def _flattened_dict(key: str, value: Any, requested_keys: Collection[str] = ()) -> Iterator[tuple[str, Any]]:
    """
    Flatten nested dicts into a single dict with keys as dotted paths.

    eg. flattened_dict({"ip": "192.168.0.1", "metric": {"ping": 3, "qos": 1}} will yield:
        * ("ip", "192.168.0.1")
        * ("metric.ping", 3)
        * ("metric.qos", 1)

    If the key to a dict value is present in requested_keys, it is also emitted.

    eg. If `request_keys` contained `"metric"` it would yield:
        * ("ip", "192.168.0.1")
        * ("metric", {"ping": 3, "qos": 1})
        * ("metric.ping", 3)
        * ("metric.qos", 1)

    """
    is_dict = isinstance(value, dict)

    # Leaves and keys of interest
    if not is_dict or key in requested_keys:
        yield key, value

    # Recurse as necessary
    if is_dict:
        for subkey, subvalue in value.items():
            yield from _flattened_dict((key + "." if key else "") + subkey, subvalue)


def yield_table(  # noqa
    result: ResultType,
    drop_fields: Collection[str] | None = None,
    table_layout: TableLayout | None = None,
    header: bool = True,
) -> Iterator[str]:
    """
    format a list of dicts in a nicer table format yielding string rows

    :param list result: List of dicts to be printed.
    :param list drop_fields: Fields to be ignored.
    :param list table_layout: Fields to be printed, could be 1D or 2D list. Examples:
        ["column1", "column2", "column3"] or
        [["column1", "column2", "column3"]] or
        [["column1", "column2", "column3"], "detail1", "detail2"]
    :param bool header: True to print the field name
    """
    drop_fields = set(drop_fields or [])

    # format all fields and collect their widths
    widths: dict[str, int] = {}
    formatted_values: list[dict[str, str]] = []
    flattened_table_layout = flatten_list(table_layout)
    for item in result:
        formatted_row: dict[str, str] = {}
        formatted_values.append(formatted_row)
        for key, value in item.items():
            if key in drop_fields:
                continue  # field will not be printed
            for subkey, subvalue in _flattened_dict(key, value, flattened_table_layout):
                if table_layout is not None and subkey not in flattened_table_layout:
                    continue  # table_layout has been specified but this field will not be printed
                formatted_row[subkey] = format_item(subkey, subvalue)
                widths[subkey] = max(len(subkey), len(formatted_row[subkey]), widths.get(subkey, 1))

    # default table layout is one row per item with sorted field names
    if table_layout is None:
        table_layout = sorted(widths)
    if not isinstance(next(iter(table_layout), []), (list, tuple)):
        table_layout = [cast(List[str], table_layout)]

    horizontal_fields: Collection[str] = next(iter(table_layout), [])
    if header:
        yield "  ".join(f.upper().ljust(widths[f]) for f in horizontal_fields)
        yield "  ".join("=" * widths[f] for f in horizontal_fields)
    for row_num, formatted_row in enumerate(formatted_values):
        # If we have multiple lines per entry yield an empty line between each entry
        if len(table_layout) > 1 and row_num > 0:
            yield ""
        # The main, horizontal, line
        yield "  ".join(formatted_row.get(f, "").ljust(widths[f]) for f in horizontal_fields).strip()
        # And the rest of the fields, one per field
        fields_to_print: list[tuple[str, str]] = []
        vertical_fields = cast(Iterator[str], itertools.islice(table_layout, 1, None))
        for vertical_field in vertical_fields:
            if vertical_field.endswith(".*"):
                for key, value in sorted(formatted_row.items()):
                    if fnmatch.fnmatch(key, vertical_field):
                        fields_to_print.append((key, value))
            else:
                value = formatted_row.get(vertical_field)
                if value is not None:
                    fields_to_print.append((vertical_field, value))
        if fields_to_print:
            max_key_width = max(len(key) for key, _ in fields_to_print)
            for key, value in fields_to_print:
                yield "    {:{}} = {}".format(key, max_key_width, value)


def print_table(
    result: Collection[Any] | ResultType | None,
    drop_fields: Collection[str] | None = None,
    table_layout: TableLayout | None = None,
    header: bool = True,
    file: TextIO | None = None,
) -> None:
    """print a list of dicts in a nicer table format"""

    def yield_rows() -> Iterator[str]:
        if not result:
            return
        elif not isinstance(next(iter(result), None), dict):
            yield from (format_item(None, item) for item in result)
        else:
            table_result = cast(ResultType, result)
            yield from yield_table(table_result, drop_fields=drop_fields, table_layout=table_layout, header=header)

    for row in yield_rows():
        print(row, file=file or sys.stdout)
