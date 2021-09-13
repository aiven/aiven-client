# Copyright (c) 2021 Aiven, Helsinki, Finland. https://aiven.io/
from aiven.client.argx import UserError
from enum import Enum

import os


class ConnectionInfoError(UserError):
    def __init__(self, message):
        super().__init__()
        self.message = message

    def __str__(self):
        return self.message


class Store(Enum):
    overwrite = object()
    write = object()
    skip = object()

    def handle(self, getter, path):
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
