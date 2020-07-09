# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from aiven.client.argx import CommandLineTool, OutputFormats

import pytest

pytestmark = [pytest.mark.unittest, pytest.mark.all]


@pytest.mark.parametrize(
    "value", [
        1,
        "a string",
        [1, 2, 3, 4, 5],
        [(1, 2), (3, 4), (5, 6)],
        ["a", "bunch", "of", "strings"],
        ["strings", "and", 1337, "numbers"],
        {
            "this": "is",
            "a": "dict"
        },
        [
            {
                "nested": {
                    "a": 1,
                    "b": 2,
                }
            },
            {
                "nested": {
                    "a": 3,
                    "b": 5,
                }
            },
        ],
        [{
            "consistent": "dictionary"
        }, {
            "consistent": "keys"
        }],
        [{
            "consistent": "dictionary"
        }, {
            "inconsistent": "keys"
        }],
    ]
)
@pytest.mark.parametrize("fmt", list(OutputFormats))
def test_print_response(request, value, fmt):
    cli = CommandLineTool(request.node.name)
    cli._output_format = fmt  # pylint: disable=protected-access
    print("\n")
    cli.print_response(value)


@pytest.mark.parametrize(
    "value", [
        ({
            "nested": {
                "a": 1,
                "b": 2,
                "e": 3,
                "f": 4,
                "g": 5
            },
        }, {
            "nested": {
                "a": 6,
                "b": 7,
                "c": 8,
                "d": 9,
                "e": 10,
                "f": 11,
            }
        }),
    ]
)
@pytest.mark.parametrize(
    "table_layout", [
        [("nested.a", "nested.b"), "nested.c", "nested.d", "nested.e", "nested.f"],
        [("nested.a", "nested.b")],
        [],
        [("something_else", "nested.b")],
        [("nested.a", "nested.b"), "something_else"],
    ]
)
@pytest.mark.parametrize(
    "fmt", [OutputFormats.TABLE, OutputFormats.TABLE_NOHEADER, OutputFormats.CSV, OutputFormats.CSV_NOHEADER]
)
def test_print_response_with_vertical_fields(request, value, fmt, table_layout):
    cli = CommandLineTool(request.node.name)
    cli._output_format = fmt  # pylint: disable=protected-access
    cli.print_response(value, table_layout=table_layout)
    print("\n")
