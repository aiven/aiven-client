# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.common_cli import AivenCommonCLI
from aiven.client.opensearch_cli import AivenOpenSearchCLI


class AivenCLI(AivenCommonCLI, AivenOpenSearchCLI):
    pass


if __name__ == "__main__":
    AivenCLI().main()
