from typing import NoReturn


def assert_never(arg: NoReturn, /) -> NoReturn:
    """
    Backport of standard library typing.assert_never.

    https://docs.python.org/3/library/typing.html#typing.assert_never
    """
    raise AssertionError("Expected code to be unreachable")
