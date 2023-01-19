"""
automatically maintains the latest git tag + revision info in a python file

"""

import importlib.machinery
import os
import re
import subprocess


def _detached() -> bool:
    try:
        # Returns exit code 1 if detached
        result = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"])
        return result.returncode == 1
    except OSError:
        return False


MAJOR_MINOR_PATCH_MATCHER = re.compile("^\d+.\d+.\d+$")


def pep440ify(git_describe_version: str) -> str:
    if git_describe_version:
        if _detached():
            if MAJOR_MINOR_PATCH_MATCHER.match(git_describe_version):
                return git_describe_version
            else:
                # If in detached state and does not match to major.minor.patch pattern
                # add some mockery to version so it is parseable by setuptools.
                return f"0.0.0+{git_describe_version}"
        else:
            version, commits, sha = git_describe_version.split("-")
            # Remove the number of commits.
            return f"{version}+{sha}"
    return git_describe_version


def get_project_version(version_file: str) -> str:
    version_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), version_file)
    try:
        module = importlib.machinery.SourceFileLoader("version", version_file).load_module()
        file_ver = module.__version__
    except:  # pylint: disable=bare-except
        file_ver = None

    try:
        proc = subprocess.Popen(
            ["git", "describe", "--always"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        if stdout:
            git_ver = stdout.splitlines()[0].strip().decode("utf-8")
            git_ver = pep440ify(git_ver)
            if git_ver and ((git_ver != file_ver) or not file_ver):
                open(version_file, "w").write("__version__ = '%s'\n" % git_ver)
                return git_ver
    except OSError:
        pass

    if not file_ver:
        raise Exception("version not available from git or from file %r" % version_file)

    return file_ver


if __name__ == "__main__":
    import sys

    get_project_version(sys.argv[1])
