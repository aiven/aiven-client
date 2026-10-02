# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""
Configurable parameters via environment variables
"""

from __future__ import annotations

from collections.abc import Mapping

import os

USER_HOME = os.path.expanduser("~")


def config_dir(env: Mapping[str, str]) -> str:
    return env.get("AIVEN_CONFIG_DIR", os.path.join(USER_HOME, ".config", "aiven"))


def client_config(env: Mapping[str, str]) -> str:
    return env.get("AIVEN_CLIENT_CONFIG", os.path.join(config_dir(env), "aiven-client.json"))


def credentials_file(env: Mapping[str, str]) -> str:
    return env.get("AIVEN_CREDENTIALS_FILE") or os.path.join(config_dir(env), "aiven-credentials.json")


def web_url(env: Mapping[str, str]) -> str:
    return env.get("AIVEN_WEB_URL", "https://api.aiven.io")


AIVEN_CONFIG_DIR = config_dir(os.environ)

AIVEN_AUTH_TOKEN = os.environ.get("AIVEN_AUTH_TOKEN")
AIVEN_CA_CERT = os.environ.get("AIVEN_CA_CERT")
AIVEN_CLIENT_CONFIG = client_config(os.environ)
AIVEN_CREDENTIALS_FILE = credentials_file(os.environ)
AIVEN_PROJECT = os.environ.get("AIVEN_PROJECT")
AIVEN_WEB_URL = web_url(os.environ)
