short_ver = 3.1.2
release = 1
PYTHON ?= python3
PYTHON_DIRS = aiven tests

test: pytest
lint: ruff flake8 mypy

reformat:
	$(PYTHON) -m isort $(PYTHON_DIRS)
	$(PYTHON) -m black $(PYTHON_DIRS)

validate-style:
	$(eval CHANGES_BEFORE := $(shell mktemp))
	git diff > $(CHANGES_BEFORE)
	$(MAKE) reformat
	$(eval CHANGES_AFTER := $(shell mktemp))
	git diff > $(CHANGES_AFTER)
	diff $(CHANGES_BEFORE) $(CHANGES_AFTER)
	-rm $(CHANGES_BEFORE) $(CHANGES_AFTER)


flake8:
	$(PYTHON) -m flake8 $(PYTHON_DIRS)

mypy:
	$(PYTHON) -m mypy $(PYTHON_DIRS)

ruff:
	$(PYTHON) -m ruff $(PYTHON_DIRS)

pytest:
	$(PYTHON) -m pytest -vv tests/

coverage:
	$(PYTHON) -m coverage run --source aiven -m pytest $(PYTEST_ARG) tests/
	$(PYTHON) -m coverage report --show-missing

clean:
	$(RM) -r rpms

build-dep-fedora:
	sudo dnf install -y --best --allowerasing \
		black \
		python3-devel \
		python3-certifi \
		python3-hatch-vcs \
		python3-hatchling \
		python3-PyMySQL \
		python3-wheel \
		python3-flake8 \
		python3-isort \
		python3-mypy \
		python3-pytest \
		python3-requests \
		python3-types-requests \
		python3-setuptools_scm \
		rpmdevtools \
		tar

rpm:
	git archive --prefix=aiven-client/ HEAD -o rpm-src-aiven-client.tar
	# add generated files to the tar, they're not in git repository
	tar -r -f rpm-src-aiven-client.tar --transform=s,aiven/,aiven-client/aiven/, $(generated)
	rpmbuild -bb aiven-client.spec \
		--define '_sourcedir $(CURDIR)' \
		--define '_rpmdir $(PWD)/rpms' \
		--define 'major_version $(short_ver)' \
		--define 'minor_version $(release)'
	$(RM) rpm-src-aiven-client.tar

.PHONY: install-rpm
install-rpm: $(RPM)
	sudo dnf install $<

.PHONY: build-dep-fedora clean coverage pytest mypy flake8 reformat test validate-style ruff
