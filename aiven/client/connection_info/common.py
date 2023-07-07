# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
from __future__ import annotations

from aiven.client.argx import UserError
from enum import Enum
from typing import Callable

import os


class ConnectionInfoError(UserError):
    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def __str__(self) -> str:
        return self.message


class Store(Enum):
    overwrite = object()
    write = object()
    skip = object()

    def handle(self, getter: Callable[[], str], path: str) -> None:
        if self is Store.overwrite:
            write = True
        elif self is Store.write:
            write = not os.path.exists(path)
        elif self is Store.skip:
            write = False
        else:
            raise NotImplementedError

        if write:
            value = getter()
            with open(path, "w", encoding="utf-8") as fob:
                fob.write(value)
