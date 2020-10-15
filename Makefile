short_ver = 2.5.0
long_ver = $(shell git describe --long 2>/dev/null || echo $(short_ver)-0-unknown-g`git describe --always`)
generated = aiven/client/version.py
PYTHON ?= python3
PYTHON_DIRS = aiven tests

all: $(generated)

aiven/client/version.py: .git/index
	$(PYTHON) version.py $@

test: flake8 pylint pytest

reformat:
	$(PYTHON) -m isort --recursive $(PYTHON_DIRS)
	yapf --parallel --recursive --in-place .

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

pylint:
	$(PYTHON) -m pylint $(PYTHON_DIRS)

pytest:
	$(PYTHON) -m pytest -vv tests/

coverage: $(generated)
	$(PYTHON) -m coverage run --source aiven -m pytest $(PYTEST_ARG) tests/
	$(PYTHON) -m coverage report --show-missing

clean:
	$(RM) -r rpms

build-dep-fedora:
	sudo dnf install -y --best --allowerasing python3-devel python3-flake8 python3-requests \
		tar rpmdevtools python3-pylint python3-isort

rpm: $(generated)
	git archive --prefix=aiven-client/ HEAD -o rpm-src-aiven-client.tar
	# add generated files to the tar, they're not in git repository
	tar -r -f rpm-src-aiven-client.tar --transform=s,aiven/,aiven-client/aiven/, $(generated)
	rpmbuild -bb aiven-client.spec \
		--define '_sourcedir $(CURDIR)' \
		--define '_rpmdir $(PWD)/rpms' \
		--define 'major_version $(short_ver)' \
		--define 'minor_version $(subst -,.,$(subst $(short_ver)-,,$(long_ver)))'
	$(RM) rpm-src-aiven-client.tar

.PHONY: build-dep-fedora clean coverage pytest pylint flake8 reformat test validate-style
