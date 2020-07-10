# Copyright 2019, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from aiven.client.pretty import format_item

import datetime
import decimal
import pytest

pytestmark = [pytest.mark.unittest, pytest.mark.all]


@pytest.mark.parametrize(
    "value,expected",
    [
        (1, "1"),
        ("a_string", "a_string"),
        (datetime.datetime(year=2019, month=12, day=23), "2019-12-23T00:00:00"),
        ([datetime.datetime(year=2019, month=12, day=23)], "2019-12-23T00:00:00"),
        (
            ["x", datetime.datetime(year=2019, month=12, day=23)],
            "x, 2019-12-23T00:00:00",
        ),
        (decimal.Decimal("64.23"), "64.23"),
        (
            {
                "a": decimal.Decimal("12.34"),
                "b": datetime.datetime(year=2019, month=12, day=23),
            },
            '{"a": "12.34", "b": "2019-12-23T00:00:00"}',
        ),
    ],
)
def test_format_item(value, expected):
    assert format_item(None, value) == expected
