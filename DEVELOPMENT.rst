Development
===========

To install all dependencies locally with ``pipenv``, run:

::

    pipenv install --three -e .

After the local virtual environment is created, run the following to "shell in" so that you can start making changes:

::

    pipenv shell

Alternatively, with ``pyenv`` and the ``pyenv-virtualenv`` plugin, create a project virtual environment and install all dependencies:

::

    pyenv virtualenv 3.13 aiven-client
    pyenv local aiven-client
    python -m pip install -e .[dev]

``pyenv local`` writes a ``.python-version`` file that auto-activates the virtual environment when you enter the directory, provided ``eval "$(pyenv virtualenv-init -)"`` is in your shell startup.

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
7. Bump the Homebrew formula in https://github.com/Homebrew/homebrew-core (``Formula/a/aiven-client.rb``). The formula pulls the sdist from PyPI, so wait until step 5 is done. Open a PR that updates the ``url`` and ``sha256`` fields to the new PyPI sdist (see the "Download files" section on https://pypi.python.org/pypi/aiven-client/X.Y.Z). Homebrew CI will build bottles and push a follow-up commit to the PR. After the PR is merged, confirm the new version at https://formulae.brew.sh/formula/aiven-client

   If you have Homebrew installed, you can use ``brew bump-formula-pr --strict aiven-client`` instead.
