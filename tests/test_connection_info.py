# Copyright 2026, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.connection_info.pg import PGConnectionInfo
from aiven.client.connection_info.valkey import ValkeyConnectionInfo
from urllib.parse import unquote, urlsplit

import pytest


@pytest.mark.parametrize("service_type", ["pg", "valkey"])
@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("app/user", "secret"),
        ("app", "p/ass"),
        ("app/user", "p/ass"),
        ("app%2Fuser", "p%2Fass"),
        ("app@?#", "p:?#"),
        ("café", "secrét"),
    ],
)
def test_connection_uri_credentials_round_trip(service_type: str, username: str, password: str) -> None:
    if service_type == "pg":
        info = PGConnectionInfo(
            host="db.example.com", port=5432, username=username, password=password, dbname="defaultdb", sslmode="require"
        )
        uri = info.uri()
        expected_port = 5432
    else:
        info_valkey = ValkeyConnectionInfo(host="db.example.com", port=6379, username=username, password=password, db="0")
        uri = info_valkey.uri()
        expected_port = 6379

    parsed = urlsplit(uri)
    assert parsed.hostname == "db.example.com"
    assert parsed.port == expected_port
    assert parsed.username is not None
    assert parsed.password is not None
    assert unquote(parsed.username) == username
    assert unquote(parsed.password) == password
    assert parsed.path == ("/defaultdb" if service_type == "pg" else "/0")
