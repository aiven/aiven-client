# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
"""
Configurable parameters via environment variables
"""

import os

USER_HOME = os.path.expanduser("~")

AIVEN_CONFIG_DIR = os.environ.get("AIVEN_CONFIG_DIR", os.path.join(USER_HOME, ".config", "aiven"))

AIVEN_AUTH_TOKEN = os.environ.get("AIVEN_AUTH_TOKEN")
AIVEN_CA_CERT = os.environ.get("AIVEN_CA_CERT")
AIVEN_CLIENT_CONFIG = os.environ.get("AIVEN_CLIENT_CONFIG", os.path.join(AIVEN_CONFIG_DIR, "aiven-client.json"))
AIVEN_CREDENTIALS_FILE = os.environ.get("AIVEN_CREDENTIALS_FILE", os.path.join(AIVEN_CONFIG_DIR, "aiven-credentials.json"))
AIVEN_PROJECT = os.environ.get("AIVEN_PROJECT")
AIVEN_WEB_URL = os.environ.get("AIVEN_WEB_URL")
