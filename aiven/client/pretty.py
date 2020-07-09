# Copyright 2015, Aiven, https://aiven.io/
# coding=utf-8
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""Pretty-print JSON objects and lists as tables"""
# string type checking must work on python 2.x and 3.x
from collections.abc import Mapping, Sequence

import datetime
import decimal
import fnmatch
import itertools
import json
import sys

try:
    basestring
except NameError:
    basestring = str  # pylint: disable=redefined-builtin


class CustomJsonEncoder(json.JSONEncoder):
    def default(self, o):  # pylint:disable=E0202
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        if isinstance(o, datetime.timedelta):
            return str(o)
        if isinstance(o, decimal.Decimal):
            return str(o)

        return json.JSONEncoder.default(self, o)


def flatten_list(val, max_depth=-1, keys=None):
    """Flatten a list out such that it can be represented as a table."""
    if keys is None:
        result = []
        for subval in val:
            result.append(flatten_list(subval, max_depth=max_depth, keys=()))
        return result

    rdict = {}
    if max_depth == -1 or len(keys) != max_depth:
        if isinstance(val, (Mapping, )):
            for key, subval in val.items():
                rdict.update(flatten_list(subval, max_depth=max_depth, keys=keys + (str(key), )))
        elif isinstance(val, (Sequence, )) and not isinstance(val, (basestring, )):
            rdict = {}
            for idx, subval in enumerate(val):
                rdict.update(flatten_list(subval, max_depth=max_depth, keys=keys + (str(idx), )))
        else:
            rdict = {".".join(keys if len(keys) > 0 else ("_raw", )): val}
        return rdict
    else:
        # Plain type should be able to render itself
        rdict = {".".join(keys if len(keys) > 0 else ("_raw", )): val}
        return rdict


def extract_fields(seq_of_maps):
    """Return the full of list fields in a possibly printed sequence"""
    seen_items = set()
    fields = []
    for item in seq_of_maps:
        fields.extend([key for key in item.keys() if key not in seen_items])
        seen_items.update(set(fields))
    return tuple(fields)


def format_item(value):
    if isinstance(value, list):
        formatted = ", ".join(format_item(entry) for entry in value)
    elif isinstance(value, dict):
        formatted = json.dumps(value, sort_keys=True, cls=CustomJsonEncoder)
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


class PreparedTableData:  # pylint: disable=too-few-public-methods
    """PreparedTableData represents prepared data for methods which render tables."""

    def __init__(self, fields, table_rows, horizontal_fields, vertical_fields):
        self.fields = fields
        self.table_rows = table_rows
        self.horizontal_fields = horizontal_fields
        self.vertical_fields = vertical_fields


def prepare_table(result, table_layout=None):
    if result is None:
        return PreparedTableData([], [], [], [])

    if not isinstance(result, Sequence) or isinstance(result, basestring):
        raise Exception("yield_table cannot render a non-sequence type argument - got: {}".format(type(result)))

        # default table layout is one row per item with sorted field names
    if table_layout is not None:
        # Treat empty layout as a null layout since it leads to less confusing behavior.
        if len(table_layout) == 0:
            table_layout = None
        else:
            if not isinstance(table_layout[0], Sequence) or isinstance(table_layout[0], basestring):
                table_layout = [table_layout]

    table_rows = flatten_list(result)
    fields = extract_fields(table_rows)

    if table_layout is None:
        table_layout = [tuple(sorted(fields))]

    horizontal_fields = tuple(str(field_name) for field_name in table_layout[0])
    vertical_fields = tuple(str(field_name) for field_name in table_layout[1:])

    return PreparedTableData(fields, table_rows, horizontal_fields, vertical_fields)


def yield_vertical_fields(formatted_row, vertical_fields):
    """Yields the rendered vertical rows of a table"""
    # And the rest of the fields, one per field
    fields_to_print = []
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
            yield "{:{}} = {}".format(key, max_key_width, value)


def yield_table(result, drop_fields=None, table_layout=None, header=True):
    """format a list of dicts in a nicer table format yielding string rows"""

    prepared_data = prepare_table(result, table_layout)

    drop_fields = set(drop_fields or [])

    # format all fields and collect their widths (start at column_name in case it's bigger)
    widths = {
        column_name: len(column_name)
        for column_name in set(prepared_data.fields).union(set(prepared_data.horizontal_fields))
    }
    formatted_rows = []

    for item in prepared_data.table_rows:
        formatted_row = {}
        for column_name in item:
            formatted_value = format_item(item[column_name])
            if widths[column_name] < len(formatted_value):
                widths[column_name] = len(formatted_value)
            if column_name not in drop_fields:
                formatted_row[column_name] = formatted_value
        formatted_rows.append(formatted_row)

    # The goal of this code is to render a table which can include named parameters as part
    # of the cell output:

    if header:
        yield "  ".join(f.upper().ljust(widths[f]) for f in prepared_data.horizontal_fields)
        yield "  ".join("=" * widths[f] for f in prepared_data.horizontal_fields)
    for row_num, formatted_row in enumerate(formatted_rows):
        # If we have multiple lines per entry yield an empty line between each entry
        if row_num > 0 and len(prepared_data.vertical_fields) > 0:
            yield ""
        # The main, horizontal, line
        row = "  ".join(formatted_row.get(f, "").ljust(widths[f]) for f in prepared_data.horizontal_fields)
        row_len = len(row)

        # Render the vertical rows as the last column of each row.
        for row, vertical_row in itertools.zip_longest([row],
                                                       yield_vertical_fields(formatted_row, prepared_data.vertical_fields)):
            if row is None:
                row = " " * row_len
            full_row = [row]
            if vertical_row is not None:
                full_row.append(vertical_row)

            yield "  ".join(full_row)


def print_table(result, drop_fields=None, table_layout=None, header=True, file=None):  # pylint: disable=redefined-builtin
    """print a list of dicts in a nicer table format"""
    for row in yield_table(result, drop_fields=drop_fields, table_layout=table_layout, header=header):
        print(row, file=file or sys.stdout)
