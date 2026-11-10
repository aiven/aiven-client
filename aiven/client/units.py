# Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from typing import Final

BYTES_IN_GIB: Final = 1_073_741_824
MIB_IN_GIB: Final = 1024


def convert_bytes_to_gib(value: float) -> float:
    return float(value) / BYTES_IN_GIB


def convert_mib_to_gib(value: float) -> float:
    return float(value) / MIB_IN_GIB
