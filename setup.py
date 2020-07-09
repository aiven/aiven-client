# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from setuptools import setup, find_packages
import sys
import version

LATEST = {
    "requests": ">= 2.9.1",
    "certifi": ">= 2015.11.20.1",
    "ruamel.yaml": ">= 0.16.5",
}

REQUIRES = LATEST.copy()

if (sys.version_info.major, sys.version_info.minor) <= (3, 4):
    # Use an older version of ruamel.yaml for Python 3.4
    REQUIRES["ruamel.yaml"] = "== 0.15.94"

if sys.platform.startswith("linux"):
    REQUIRES["requests"] = ">= 2.2.1"  # minimum defined by Ubuntu Trusty (14.04LTS)
    # No bundled certifi as distro packages are expected to be patched to use system ca certs
    REQUIRES.pop("certifi")

setup(
    author="Aiven",
    author_email="support@aiven.io",
    entry_points={
        "console_scripts": [
            "avn = aiven.client.__main__:main",
        ],
    },
    install_requires=["{} {}".format(name, version) for name, version in REQUIRES.items()],
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
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)
