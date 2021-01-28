# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from setuptools import setup, find_packages
import sys
import version

LATEST = [
    "requests >= 2.9.1",
    "certifi >= 2015.11.20.1",
]

if sys.platform.startswith("linux"):
    REQUIRES = [
        # no bundled certifi as distro packages are expected to be patched to use system ca certs
        "requests >= 2.2.1",  # minimum defined by Ubuntu Trusty (14.04LTS)
    ]
elif sys.platform == "darwin":
    REQUIRES = LATEST
elif sys.platform.startswith("win"):
    REQUIRES = LATEST
else:
    # default to latest version on unknown platforms
    REQUIRES = LATEST

setup(
    author="Aiven",
    author_email="support@aiven.io",
    entry_points={
        "console_scripts": [
            "avn = aiven.client.__main__:main",
        ],
    },
    install_requires=REQUIRES,
    license="Apache 2.0",
    name="aiven-client",
    packages=find_packages(exclude=["tests"]),
    platforms=["POSIX", "MacOS", "Windows"],
    description="Aiven.io client library / command-line client",
    long_description=open("README.rst").read(),
    url="https://aiven.io/",
    version=version.get_project_version("aiven/client/version.py"),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
