Development
===========

To install all dependencies locally with ``pipenv``, run:

::

    pipenv install --three -e .

After the local virtual environment is created, run the following to "shell in" so that you can start making changes:

::

    pipenv shell

Releasing a new version
=======================

Only authorised users can release a new version Aiven Client.

Steps to release.

Let's say the version to be released is ``X.Y.Z``.

1. Edit ``Makefile`` and set ``short_ver`` to value ``X.Y.Z``. Commit the change with a commit message ``Release version X.Y.Z``.
2. Create an annotated tag with: ``git tag -a -m "version X.Y.Z" X.Y.Z``
3. Push the commit and tag to GitHub: ``git push origin main X.Y.Z``. This will trigger the GitHub actions to build and publish the package to PyPI.
4. Wait for the GitHub actions to finish
5. Check that GitHub Publish to PyPI Action succeeded. Confirm the package looks correct at https://pypi.python.org/pypi/aiven-client
6. Add Release in GitHub UI at https://github.com/aiven/aiven-client/releases
