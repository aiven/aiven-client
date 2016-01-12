# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from setuptools import setup, find_packages
import os
import version

setup(
    author="Aiven",
    author_email="support@aiven.io",
    entry_points={
        "console_scripts": [
            "avn = aiven.client.__main__:main",
        ],
    },
    install_requires=["requests >= 1.2.0"],
    license="Apache 2.0",
    name="aiven-client",
    packages=find_packages(exclude=["tests"]),
    url="https://aiven.io/",
    version=version.get_project_version("aiven/client/version.py"),
)
