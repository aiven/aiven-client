# Copyright 2019, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from aiven.client.pretty import flatten_list, format_item, print_table

import datetime
import decimal
import io
import ipaddress
import pytest
import re


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
        (ipaddress.IPv4Address("192.168.0.1"), "192.168.0.1"),
        (ipaddress.IPv6Address("fd00:0000::1:123"), "fd00::1:123"),
        (ipaddress.IPv4Network("192.168.0.0/24"), "192.168.0.0/24"),
        (ipaddress.IPv6Network("fd00:0:1::/120"), "fd00:0:1::/120"),
    ],
)
def test_format_item(value, expected):
    assert format_item(None, value) == expected


def test_flatten_list():
    original_list = [["column1", "column2", "column3"], "detail1", "detail2"]
    flat_list = flatten_list(original_list)
    assert original_list == [["column1", "column2", "column3"], "detail1", "detail2"]  # ensure it doesn't have side effects
    assert flat_list == ["column1", "column2", "column3", "detail1", "detail2"]


def test_print_table():
    """Print table, ensure we don't try to format non-visible field"""
    rows = []
    rows.append({
        "ip": ipaddress.IPv4Address("192.168.16.1"),
        "network": ipaddress.IPv4Network("192.168.16.0/20"),
        "metric": 1,
        "next_hop_ip": ipaddress.IPv4Address("192.168.16.2"),
        "next_hop_mac": "0c:d0:f8:a3:04:31",
        "function1": test_print_table
    })
    rows.append({
        "ip": ipaddress.IPv4Address("10.0.0.1"),
        "network": ipaddress.IPv4Network("10.0.0.0/16"),
        "metric": 100,
        "function2": test_print_table
    })

    def get_output(rows, *, drop_fields=None, table_layout=None):
        temp_io = io.StringIO()
        print_table(rows, drop_fields=drop_fields, table_layout=table_layout, file=temp_io)
        temp_io.seek(0)
        return temp_io.read()

    def fuzzy_compare_assert(actual, expected):
        cleanup_actual = re.sub(r" +$", "", actual.strip(), flags=re.MULTILINE)
        cleanup_expected = re.sub(r" +$", "", expected.strip(), flags=re.MULTILINE)
        assert cleanup_actual == cleanup_expected

    actual = get_output(rows, drop_fields=["function1", "function2"])
    expected = """
IP            METRIC  NETWORK          NEXT_HOP_IP   NEXT_HOP_MAC
============  ======  ===============  ============  =================
192.168.16.1  1       192.168.16.0/20  192.168.16.2  0c:d0:f8:a3:04:31
10.0.0.1      100     10.0.0.0/16
"""
    fuzzy_compare_assert(actual, expected)

    actual = get_output(rows, table_layout=["ip", "network", "metric"])
    expected = """
IP            NETWORK          METRIC
============  ===============  ======
192.168.16.1  192.168.16.0/20  1
10.0.0.1      10.0.0.0/16      100
"""
    fuzzy_compare_assert(actual, expected)

    actual = get_output(rows, table_layout=[["ip", "network", "metric"], "next_hop_ip", "next_hop_mac"])
    expected = """
IP            NETWORK          METRIC
============  ===============  ======
192.168.16.1  192.168.16.0/20  1
    next_hop_ip  = 192.168.16.2
    next_hop_mac = 0c:d0:f8:a3:04:31

10.0.0.1      10.0.0.0/16      100
"""
    fuzzy_compare_assert(actual, expected)

    with pytest.raises(TypeError):
        get_output(rows)
