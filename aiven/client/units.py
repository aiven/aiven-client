# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from typing import Final

MIB_IN_GIB: Final = 1024


def convert_mib_to_gib(value: float | int) -> float:
    return float(value) / MIB_IN_GIB
