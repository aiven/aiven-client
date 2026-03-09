# Contributing to aiven-client

When contributing to this repository, follow the guidelines below and in [AGENTS.md](AGENTS.md).

## Project Overview

Python CLI (`avn`) for managing Aiven cloud services. Built on argparse, talks to the Aiven REST API. Python 3.9+.

## Build & Test

```bash
make install-py      # Install with dev dependencies
make test            # Run pytest
make lint            # Run ruff + flake8 + mypy
make reformat        # Auto-format with black + isort
make all             # Full pipeline: install, validate-style, lint, test
make coverage        # Test with coverage report
```

## Source Layout

| File | Purpose |
|------|---------|
| `aiven/client/cli.py` | All CLI command methods (~7000 lines, single file) |
| `aiven/client/argx.py` | Base CLI framework: argument parsing, `print_response`, `UserError`, `Config` |
| `aiven/client/cliarg.py` | Shared argument decorators (`@arg.project`, `@arg.force`, etc.) |
| `aiven/client/client.py` | REST API client — all HTTP calls to Aiven API |
| `aiven/client/pretty.py` | Table formatting and output helpers |
| `aiven/client/validation.py` | Resource ID validation (anti-path-traversal) |
| `aiven/client/envdefault.py` | Environment variable defaults for arguments |
| `aiven/client/common.py` | Shared constants (e.g. `UNDEFINED` sentinel) |
| `aiven/client/session.py` | HTTP session management |
| `aiven/client/connection_info/` | Service-specific connection string builders (pg, kafka, valkey) |
| `tests/test_cli.py` | Main CLI test suite |
| `tests/test_argx.py` | Framework-level tests |
| `tests/test_cliarg.py` | Argument decorator tests |
| `tests/test_validation.py` | Resource ID validation tests |

## How to Add a New Command

1. **Naming:** Define a method in `cli.py` named `group__subcommand`. Double underscores map to spaces: `service__topic_create` becomes `avn service topic-create`. Single underscores become hyphens in the CLI.

2. **Arguments:** Decorate with shared args from `cliarg.py`:
   ```python
   @arg.project
   @arg.service_name
   @arg("--my-flag", help="Description")
   def service__my_command(self) -> None:
       """Docstring becomes the help text."""
   ```

3. **API call:** Use `self.client()` to get the API client:
   ```python
   result = self.client().get_service(
       project=self.get_project(),
       service=self.args.service_name,
   )
   ```

4. **Output:** Use `self.print_response()` for structured output:
   ```python
   self.print_response(
       result,
       json=self.args.json,
       table_layout=[...],
   )
   ```

5. **Test:** Add to `tests/test_cli.py`:
   ```python
   def test_my_command():
       aiven_client = mock.Mock(spec_set=AivenClient)
       aiven_client.get_service.return_value = {"name": "svc1"}
       cli = build_aiven_cli(aiven_client)
       cli.run(args=["service", "my-command", "svc1", "--project", "proj"])
       aiven_client.get_service.assert_called_once()
   ```

## How to Add a Shared Argument

In `cliarg.py`, add to the `arg` namespace:

```python
arg.my_arg = arg(
    "--my-arg",
    help="Description of the argument",
    default=None,
)
```

Then use as a decorator: `@arg.my_arg` on command methods.

For validated positional arguments (resource IDs), use `validated_resource_id`:

```python
arg("resource_name", help="Resource name", type=validated_resource_id("resource_name"))
```

## Coding Conventions

- **Method naming:** `group__subcommand` (double underscore = space, single underscore = hyphen)
- **Project resolution:** Always use `self.get_project()`, never `self.args.project` directly
- **API access:** `self.client()` returns the authenticated `AivenClient`
- **Output:** `self.print_response()` handles JSON, table, CSV, and format string output
- **Errors:** Raise `UserError("message")` for user-facing errors (from `aiven.client.argx`)
- **Config:** `arg.project` uses `envdefault.AIVEN_PROJECT` for env var fallback

## Testing Patterns

```python
from aiven.client import AivenClient
from aiven.client.cli import AivenCLI, ClientFactory
from collections.abc import Iterator
from contextlib import contextmanager
from unittest import mock
from typing import Any

# Build CLI with mocked API client
def build_aiven_cli(client: AivenClient) -> AivenCLI:
    cli = AivenCLI(client_factory=mock.Mock(spec_set=ClientFactory, return_value=client))
    cli._get_auth_token = lambda *a, **kw: "mock-token"
    return cli

# Mock project config
@contextmanager
def mock_config(return_value: Any) -> Iterator[None]:
    with mock.patch("aiven.client.argx.Config", side_effect=lambda _: return_value):
        yield

# Typical test
def test_example(capsys):
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.get_services.return_value = [{"service_name": "svc1", "state": "RUNNING"}]
    cli = build_aiven_cli(aiven_client)
    with mock_config({"default_project": "proj"}):
        cli.run(args=["service", "list", "--project", "proj"])
    captured = capsys.readouterr()
    assert "svc1" in captured.out
```

## Agent-Ready Checklist for New Commands

When adding or modifying commands, ensure:

- [ ] `--json` output works (use `self.print_response()` with `json=self.args.json`)
- [ ] Destructive commands support `--dry-run` and `--force`
- [ ] Positional resource IDs use `validated_resource_id()` type
- [ ] Non-zero exit code on failure
- [ ] Update the relevant skill file in `skills/avn-*/SKILL.md`
- [ ] Update `AGENTS.md` if adding a new command group

## Commit Conventions

```
<type>: <description>

<optional body>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

## Style & Formatting

The project uses black, isort, ruff, flake8, and mypy. Run `make reformat` before committing. Run `make all` to verify everything passes.
