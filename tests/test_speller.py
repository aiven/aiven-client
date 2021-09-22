# Copyright 2021, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from aiven.client.speller import suggest

import pytest

# Current service types (2021-03-09); they are used just for testing
SERVICE_TYPES = [
    "alerta",
    "cassandra",
    "elasticsearch",
    "grafana",
    "influxdb",
    "kafka",
    "kafka_connect",
    "kafka_mirrormaker",
    "m3db",
    "m3coordinator",
    "m3aggregator",
    "mysql",
    "pg",
    "redis",
    "sw",
    "flink",
]


@pytest.mark.parametrize(
    ["word_to_check", "known_words", "suggestion"],
    [
        ("kafka", SERVICE_TYPES, "kafka"),
        ("kakfa", SERVICE_TYPES, "kafka"),
        ("kafkaconnect", SERVICE_TYPES, "kafka_connect"),
        ("kafka-connect", SERVICE_TYPES, "kafka_connect"),
        ("asdf", SERVICE_TYPES, None),
    ],
)
def test_suggest(word_to_check, known_words, suggestion):
    assert suggest(word_to_check=word_to_check, known_words=known_words) == suggestion
