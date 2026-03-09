# Agent-Ready aiven-client Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make aiven-client score 11+ on the Agent DX CLI Scale (Agent-ready) while maintaining 100% backward compatibility for existing human users and SRE workflows.

**Architecture:** Each task adds one isolated, independently testable capability to the CLI framework layer (`argx.py`, `pretty.py`, `cliarg.py`). No changes to individual command methods in `cli.py` unless absolutely required. All new behavior is opt-in via flags or non-TTY detection — existing default behavior is preserved.

**Tech Stack:** Python 3.9+, argparse, pytest, unittest.mock

**Critical constraint:** Both Aiven platform users and internal SRE rely on this CLI. Every change must be backward-compatible. Human-facing defaults must not change. All new behavior must be tested against the existing test suite plus new tests.

---

## Phase 1: Structured Output (Score: 0→2 on Machine-Readable Output axis)

### Task 1: Auto-detect non-TTY and emit JSON by default

When stdout is piped (not a TTY), `print_response` should default to JSON output. This means agents piping `avn` output get structured data without remembering `--json`.

**Files:**
- Modify: `aiven/client/argx.py:315-339` (print_response method)
- Modify: `aiven/client/argx.py:231-237` (add `--no-auto-json` top-level arg)
- Test: `tests/test_argx.py`

**Step 1: Write the failing test**

Add to `tests/test_argx.py`:

```python
import io
from unittest import mock

from aiven.client.argx import CommandLineTool


class TestPrintResponseAutoJson:
    """When stdout is not a TTY, print_response should emit JSON by default."""

    def _make_tool(self) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.no_auto_json = False
        return tool

    def test_non_tty_emits_json(self):
        """When file is non-TTY and json=False, output should still be JSON."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        import json
        output = buf.getvalue()
        parsed = json.loads(output)
        assert parsed == [{"name": "svc1", "plan": "hobby"}]

    def test_tty_emits_table(self):
        """When file is a TTY and json=False, output should be a table."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        # Table output contains column headers, not JSON brackets
        assert "name" in output.lower()
        assert not output.strip().startswith("[")

    def test_explicit_json_true_always_emits_json(self):
        """When json=True explicitly, always emit JSON regardless of TTY."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1"}],
            json=True,
            file=buf,
        )
        import json
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1"}]

    def test_no_auto_json_flag_disables_detection(self):
        """--no-auto-json should preserve table output even in non-TTY."""
        tool = self._make_tool()
        tool.args.no_auto_json = True
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        assert not output.strip().startswith("[")

    def test_format_string_overrides_auto_json(self):
        """When --format is given, it takes priority over auto-JSON."""
        tool = self._make_tool()
        buf = io.StringIO()
        buf.isatty = lambda: False  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1"}],
            json=False,
            format="{name}",
            file=buf,
        )
        assert buf.getvalue().strip() == "svc1"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_argx.py::TestPrintResponseAutoJson -v`
Expected: FAIL — `no_auto_json` attribute doesn't exist, non-TTY still emits table

**Step 3: Write minimal implementation**

In `aiven/client/argx.py`, modify the `__init__` method of `CommandLineTool` (line 226-237) to add the flag:

```python
self.parser.add_argument(
    "--no-auto-json",
    help="Disable automatic JSON output in non-TTY (piped) contexts",
    action="store_true",
    default=False,
)
```

In `aiven/client/argx.py`, modify `print_response` (line 315-361). Add auto-detection after the `file` default (line 328-329):

```python
def print_response(
    self,
    result: Mapping[str, Any] | Collection[Mapping[str, Any]],
    json: bool = True,
    format: str | None = None,
    drop_fields: Collection[str] | None = None,
    table_layout: TableLayout | None = None,
    single_item: bool = False,
    header: bool = True,
    csv: bool = False,
    file: TextIO | None = None,
) -> None:
    """print request response in chosen format"""
    if file is None:
        file = sys.stdout

    # Auto-detect non-TTY: emit JSON when piped, unless explicitly disabled
    no_auto_json = getattr(self.args, "no_auto_json", False)
    if not json and not no_auto_json and not csv and format is None:
        if hasattr(file, "isatty") and not file.isatty():
            json = True

    if format is not None:
        # ... rest unchanged
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_argx.py::TestPrintResponseAutoJson -v`
Expected: PASS

**Step 5: Run the full existing test suite for regressions**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — existing tests use `capsys` which is a non-TTY `StringIO`, but they explicitly pass `json=self.args.json` so the `json` parameter is already `True` or `False` explicitly. The auto-detection only fires when `json=False` AND non-TTY, and most test helpers mock `self.args.json` as `False` with table assertions. Verify carefully.

**Step 6: Commit**

```
feat: auto-detect non-TTY and emit JSON output when piped

Agents and scripts piping avn output now get structured JSON
automatically. Human users in terminals see tables as before.
Disable with --no-auto-json if needed.
```

---

### Task 2: Structured JSON error output in non-TTY contexts

When errors occur and stdout is non-TTY, emit a JSON error object to stdout instead of only logging plain text to stderr. This lets agents parse failure reasons.

**Files:**
- Modify: `aiven/client/argx.py:363-393` (run method)
- Test: `tests/test_argx.py`

**Step 1: Write the failing test**

Add to `tests/test_argx.py`:

```python
import json
import io
import sys
from unittest import mock

from aiven.client.argx import CommandLineTool, UserError
from aiven.client import client as aiven_client


class TestStructuredErrorOutput:
    """In non-TTY contexts, errors should be emitted as JSON to stdout."""

    def _make_tool_that_raises(self, exception: Exception) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.config = "/dev/null"
        tool.args.no_auto_json = False
        # Make run_actual raise the exception
        tool.run_actual = mock.Mock(side_effect=exception)
        tool.parse_args = mock.Mock()
        tool.config = mock.Mock()
        return tool

    def test_user_error_json_on_non_tty(self):
        """UserError should produce JSON error on non-TTY stdout."""
        tool = self._make_tool_that_raises(UserError("project not found"))
        buf = io.StringIO()
        buf.isatty = lambda: False

        with mock.patch("sys.stdout", buf):
            exit_code = tool.run(args=["some", "command"])

        assert exit_code == 1
        output = buf.getvalue()
        parsed = json.loads(output)
        assert parsed["error"] is True
        assert "project not found" in parsed["message"]
        assert parsed["exit_code"] == 1

    def test_user_error_plain_on_tty(self):
        """UserError should NOT produce JSON on TTY stdout (backward compat)."""
        tool = self._make_tool_that_raises(UserError("project not found"))
        buf = io.StringIO()
        buf.isatty = lambda: True

        with mock.patch("sys.stdout", buf):
            exit_code = tool.run(args=["some", "command"])

        assert exit_code == 1
        # No JSON on stdout in TTY mode
        assert buf.getvalue() == ""

    def test_client_error_includes_status(self):
        """client.Error should include HTTP status in JSON error."""
        resp = mock.Mock()
        resp.text = '{"message": "forbidden"}'
        error = aiven_client.Error(resp, status=403)
        tool = self._make_tool_that_raises(error)
        buf = io.StringIO()
        buf.isatty = lambda: False

        with mock.patch("sys.stdout", buf):
            exit_code = tool.run(args=["some", "command"])

        assert exit_code == 1
        parsed = json.loads(buf.getvalue())
        assert parsed["error"] is True
        assert parsed["status"] == 403
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_argx.py::TestStructuredErrorOutput -v`
Expected: FAIL — no JSON error output exists yet

**Step 3: Write minimal implementation**

In `aiven/client/argx.py`, add a helper and modify the `run` method error handler:

```python
def _emit_json_error(self, message: str, exit_code: int, status: int | None = None) -> None:
    """Emit structured JSON error to stdout if in non-TTY context."""
    no_auto_json = getattr(self.args, "no_auto_json", False)
    if no_auto_json:
        return
    if hasattr(sys.stdout, "isatty") and not sys.stdout.isatty():
        error_obj: dict[str, Any] = {
            "error": True,
            "message": message,
            "exit_code": exit_code,
        }
        if status is not None:
            error_obj["status"] = status
        print(jsonlib.dumps(error_obj, indent=4, sort_keys=True), file=sys.stdout)
```

Modify the `except` block in `run()` (lines 381-384):

```python
except tuple(expected_errors) as ex:
    err = "command failed: {0.__class__.__name__}: {0}".format(ex)
    self.log.error(err)
    status = getattr(ex, "status", None)
    self._emit_json_error(str(ex), exit_code=1, status=status)
    return 1
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_argx.py::TestStructuredErrorOutput -v`
Expected: PASS

**Step 5: Run full test suite for regressions**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — existing tests capture stderr via `caplog`, stdout via `capsys`. JSON error output goes to stdout only in non-TTY. The `capsys` fixture is non-TTY, so existing tests that check `caplog.text` for error messages still work (logging still happens). But verify that no existing test asserts stdout is empty after an error.

**Step 6: Commit**

```
feat: emit structured JSON errors to stdout in non-TTY contexts

Agents piping avn output can now parse error responses as JSON.
Human users in terminals see the same stderr log messages as before.
```

---

## Phase 2: Context Window Discipline (Score: 0→1 on Context Window axis)

### Task 3: Add `--fields` flag to filter output columns

Add a top-level `--fields` argument that filters which keys appear in JSON and table output.

**Files:**
- Modify: `aiven/client/argx.py:226-237` (add --fields arg to parser)
- Modify: `aiven/client/argx.py:315-361` (filter in print_response)
- Test: `tests/test_argx.py`

**Step 1: Write the failing test**

Add to `tests/test_argx.py`:

```python
class TestFieldsFiltering:
    """--fields should filter output to only requested keys."""

    def _make_tool(self, fields: str | None = None) -> CommandLineTool:
        tool = CommandLineTool("test")
        tool.args = mock.Mock()
        tool.args.no_auto_json = True
        tool.args.fields = fields
        return tool

    def test_fields_filters_json_output(self):
        tool = self._make_tool(fields="name,plan")
        buf = io.StringIO()
        buf.isatty = lambda: True
        tool.print_response(
            [{"name": "svc1", "plan": "hobby", "state": "RUNNING", "cloud": "aws"}],
            json=True,
            file=buf,
        )
        import json
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1", "plan": "hobby"}]

    def test_fields_filters_table_output(self):
        tool = self._make_tool(fields="name,plan")
        buf = io.StringIO()
        buf.isatty = lambda: True
        tool.print_response(
            [{"name": "svc1", "plan": "hobby", "state": "RUNNING"}],
            json=False,
            file=buf,
        )
        output = buf.getvalue()
        assert "svc1" in output
        assert "RUNNING" not in output

    def test_no_fields_returns_all(self):
        tool = self._make_tool(fields=None)
        buf = io.StringIO()
        buf.isatty = lambda: True
        tool.print_response(
            [{"name": "svc1", "state": "RUNNING"}],
            json=True,
            file=buf,
        )
        import json
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1", "state": "RUNNING"}]

    def test_fields_single_item(self):
        tool = self._make_tool(fields="name")
        buf = io.StringIO()
        buf.isatty = lambda: True
        tool.print_response(
            {"name": "svc1", "plan": "hobby"},
            json=True,
            single_item=True,
            file=buf,
        )
        import json
        parsed = json.loads(buf.getvalue())
        assert parsed == [{"name": "svc1"}]
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_argx.py::TestFieldsFiltering -v`
Expected: FAIL — `fields` attribute doesn't exist, no filtering logic

**Step 3: Write minimal implementation**

Add to `CommandLineTool.__init__` in `argx.py`:

```python
self.parser.add_argument(
    "--fields",
    help="Comma-separated list of fields to include in output (e.g. --fields name,plan,state)",
    default=None,
)
```

Add a filtering helper method to `CommandLineTool`:

```python
def _apply_field_filter(
    self, result: Collection[Mapping[str, Any]]
) -> Collection[Mapping[str, Any]]:
    """Filter result dicts to only include requested fields."""
    fields_str = getattr(self.args, "fields", None)
    if not fields_str:
        return result
    fields = {f.strip() for f in fields_str.split(",")}
    return [{k: v for k, v in item.items() if k in fields} for item in result]
```

Modify `print_response` to call the filter before any output path. Insert after the auto-json detection block, before the `if format is not None:` line:

```python
# Apply field filtering if --fields was provided
result_collection = self._to_mapping_collection(result, single_item=single_item)
result_collection = self._apply_field_filter(result_collection)
# Use filtered collection for all output paths below
single_item = False  # already converted to collection
```

Then replace all references to `result` in the output paths with `result_collection`, and remove the `_to_mapping_collection` calls since it's already been converted.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_argx.py::TestFieldsFiltering -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — `fields` defaults to `None`, so no filtering unless explicitly requested

**Step 6: Commit**

```
feat: add --fields flag to filter output columns

Allows agents and scripts to request only the fields they need,
reducing output size. Example: avn service list --fields name,state
```

---

## Phase 3: Safety Rails (Score: 0→1 on Safety Rails axis)

### Task 4: Add `--dry-run` to destructive commands

Add a `--dry-run` flag that prints what would be done without executing the API call. Start with the most dangerous commands: `service terminate`, `project delete`, `organization delete`.

**Files:**
- Modify: `aiven/client/cliarg.py` (add arg.dry_run)
- Modify: `aiven/client/cli.py:3626-3647` (service__terminate)
- Modify: `aiven/client/cli.py` (project__delete, organization__delete)
- Test: `tests/test_cli.py`

**Step 1: Write the failing test**

Add to `tests/test_cli.py`:

```python
class TestDryRun:
    """--dry-run should print the action without executing it."""

    def test_service_terminate_dry_run(self, capsys: CaptureFixture[str]):
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            result = cli.run(args=[
                "service", "terminate", "--force", "--dry-run", "my-service"
            ])
        assert result is None
        # API should NOT have been called
        aiven_client.delete_service.assert_not_called()
        # Output should describe what would happen
        captured = capsys.readouterr()
        assert "my-service" in captured.out
        assert "dry-run" in captured.out.lower() or "dry_run" in captured.out.lower()

    def test_service_terminate_without_dry_run(self, capsys: CaptureFixture[str]):
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            result = cli.run(args=[
                "service", "terminate", "--force", "my-service"
            ])
        # API SHOULD have been called
        aiven_client.delete_service.assert_called_once()

    def test_project_delete_dry_run(self, capsys: CaptureFixture[str]):
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({}):
            result = cli.run(args=[
                "project", "delete", "--dry-run", "my-project"
            ])
        assert result is None
        aiven_client.delete_project.assert_not_called()
        captured = capsys.readouterr()
        assert "my-project" in captured.out
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py::TestDryRun -v`
Expected: FAIL — `--dry-run` not recognized

**Step 3: Write minimal implementation**

In `aiven/client/cliarg.py`, add the shared argument:

```python
arg.dry_run = arg(
    "--dry-run",
    help="Show what would be done without executing the action",
    action="store_true",
    default=False,
)
```

In `aiven/client/cli.py`, modify `service__terminate` (around line 3626):

```python
@arg.project
@arg.force
@arg.dry_run
@arg("service_name", help="Service name", nargs="+")
def service__terminate(self) -> None:
    """Terminate service"""
    if self.args.dry_run:
        for name in self.args.service_name:
            print(
                "dry-run: would terminate service {!r} in project {!r}".format(
                    name, self.get_project()
                )
            )
        return

    if not self.args.force and os.environ.get("AIVEN_FORCE") != "true":
        # ... existing confirmation logic unchanged
```

Apply similar pattern to `project__delete` and `organization__delete`.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py::TestDryRun -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — `--dry-run` defaults to `False`

**Step 6: Commit**

```
feat: add --dry-run to service terminate, project delete, org delete

Agents can now validate destructive operations before executing them.
When --dry-run is passed, the CLI prints what would happen without
making any API calls.
```

---

## Phase 4: Input Hardening (Score: 0→1 on Input Hardening axis)

### Task 5: Validate resource IDs against agent hallucination patterns

Add a centralized validator that rejects path traversal, control characters, percent-encoded segments, and embedded query params in resource identifiers.

**Files:**
- Create: `aiven/client/validation.py`
- Modify: `aiven/client/cli.py:146-177` (call validator in pre_run)
- Test: `tests/test_validation.py`

**Step 1: Write the failing test**

Create `tests/test_validation.py`:

```python
import pytest

from aiven.client.validation import validate_resource_id


class TestValidateResourceId:
    """Resource IDs must reject agent hallucination patterns."""

    @pytest.mark.parametrize("valid_id", [
        "my-service",
        "my_service_123",
        "ProductionDB",
        "pg-us-east-1",
        "a",
        "service-with.dot",
    ])
    def test_accepts_valid_ids(self, valid_id: str):
        # Should not raise
        validate_resource_id(valid_id, "service_name")

    @pytest.mark.parametrize("bad_id,reason", [
        ("../etc/passwd", "path traversal"),
        ("..%2f..%2fetc", "percent-encoded traversal"),
        ("service?admin=true", "embedded query param"),
        ("service#fragment", "embedded fragment"),
        ("service\x00name", "null byte"),
        ("service\nname", "newline"),
        ("service\tname", "tab"),
        ("%2e%2e/secret", "percent-encoded dots"),
        ("", "empty string"),
        ("   ", "whitespace only"),
    ])
    def test_rejects_dangerous_ids(self, bad_id: str, reason: str):
        with pytest.raises(ValueError, match="Invalid resource identifier"):
            validate_resource_id(bad_id, "service_name")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_validation.py -v`
Expected: FAIL — module does not exist

**Step 3: Write minimal implementation**

Create `aiven/client/validation.py`:

```python
"""Input validation for resource identifiers.

Rejects patterns commonly produced by LLM hallucinations:
path traversal, percent-encoded segments, embedded query params,
control characters, and empty/whitespace-only strings.
"""
from __future__ import annotations

import re

# Control characters (U+0000 to U+001F and U+007F)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# Percent-encoded sequences (e.g., %2e, %2f)
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")

# Embedded query string or fragment
_QUERY_FRAGMENT_RE = re.compile(r"[?#]")


def validate_resource_id(value: str, field_name: str) -> str:
    """Validate a resource identifier against common hallucination patterns.

    Raises ValueError if the value contains dangerous patterns.
    Returns the value unchanged if valid.
    """
    if not value or not value.strip():
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: must not be empty"
        )

    if ".." in value:
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: "
            f"path traversal sequence '..' is not allowed"
        )

    if _PERCENT_ENCODED_RE.search(value):
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: "
            f"percent-encoded characters are not allowed"
        )

    if _QUERY_FRAGMENT_RE.search(value):
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: "
            f"query parameters '?' and fragments '#' are not allowed"
        )

    if _CONTROL_CHAR_RE.search(value):
        raise ValueError(
            f"Invalid resource identifier for {field_name!r}: "
            f"control characters are not allowed"
        )

    return value
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_validation.py -v`
Expected: PASS

**Step 5: Commit**

```
feat: add resource ID validation against hallucination patterns

Rejects path traversal, percent-encoded segments, embedded query
params, control characters, and empty strings in resource identifiers.
```

---

### Task 6: Wire resource ID validation into CLI argument parsing

Apply `validate_resource_id` to the most critical positional arguments: `service_name`, `project`, topic, database names.

**Files:**
- Modify: `aiven/client/cliarg.py` (add validated type function)
- Test: `tests/test_cliarg.py`

**Step 1: Write the failing test**

Add to `tests/test_cliarg.py`:

```python
import pytest
from aiven.client.cliarg import validated_resource_id


class TestValidatedResourceId:
    """validated_resource_id should be usable as an argparse type."""

    def test_valid_name_passes_through(self):
        validator = validated_resource_id("service_name")
        assert validator("my-service") == "my-service"

    def test_path_traversal_raises(self):
        validator = validated_resource_id("service_name")
        # argparse wraps type errors, so we check ValueError
        with pytest.raises(ValueError):
            validator("../etc/passwd")

    def test_empty_string_raises(self):
        validator = validated_resource_id("service_name")
        with pytest.raises(ValueError):
            validator("")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cliarg.py::TestValidatedResourceId -v`
Expected: FAIL — `validated_resource_id` does not exist

**Step 3: Write minimal implementation**

In `aiven/client/cliarg.py`, add:

```python
from aiven.client.validation import validate_resource_id


def validated_resource_id(field_name: str) -> Callable[[str], str]:
    """Return an argparse type function that validates resource IDs."""
    def _validate(value: str) -> str:
        return validate_resource_id(value, field_name)
    _validate.__name__ = f"resource_id({field_name})"
    return _validate
```

Then update the key positional argument definitions:

```python
arg.service_name = arg("service_name", help="Service name", type=validated_resource_id("service_name"))
arg.topic = arg("topic", help="Topic name", type=validated_resource_id("topic"))
arg.index_name = arg("index_name", help="Index name", type=validated_resource_id("index_name"))
arg.ns_name = arg("ns_name", help="Namespace name", type=validated_resource_id("ns_name"))
```

**Important:** Do NOT add validation to `arg.project` — it uses `--project` with a default from `os.environ`, and `None` must pass through. The project value is validated later via `get_project()`.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cliarg.py::TestValidatedResourceId -v`
Expected: PASS

**Step 5: Run full test suite (critical — this touches argument parsing)**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — existing tests use valid service names. If any tests use names that now fail validation, fix the test data (not the validator).

**Step 6: Commit**

```
feat: validate service_name, topic, index_name against hallucinations

Positional resource ID arguments now reject path traversal, percent
encoding, control characters, and embedded query params at parse time.
```

---

## Phase 5: Agent Knowledge Packaging (Score: 0→1 on Knowledge axis)

### Task 7: Create AGENTS.md with agent-facing documentation

Ship an `AGENTS.md` at repository root with structured guidance for AI agents consuming this CLI.

**Files:**
- Create: `AGENTS.md`

**Step 1: Write AGENTS.md**

```markdown
# Agent Guide for aiven-client (`avn`)

## Authentication

Set these environment variables for headless (non-interactive) use:

```
AIVEN_AUTH_TOKEN=<your-token>    # Required: API authentication token
AIVEN_PROJECT=<default-project>  # Optional: default project for all commands
```

Tokens can be created via: `avn user access-token create --description "agent" --json`

## Output

- **Non-TTY (piped) contexts** automatically emit JSON. No `--json` flag needed.
- Force table output in pipes with `--no-auto-json`.
- Errors in non-TTY contexts are emitted as JSON to stdout: `{"error": true, "message": "...", "exit_code": 1}`
- Filter output fields with `--fields name,state,plan` to reduce token usage.

## Destructive Commands

These commands support `--dry-run`:
- `avn service terminate --dry-run <name>`
- `avn project delete --dry-run <name>`
- `avn organization delete --dry-run <name>`

**Always use `--dry-run` first, then `--force` to skip interactive confirmation.**

## Common Workflows

### List services (agent-optimized)
```
avn service list --project myproject --fields service_name,state,plan,cloud_name
```

### Get service details
```
avn service get myservice --project myproject --fields service_name,state,service_uri
```

### Create a service
```
avn service create myservice --project myproject --service-type pg --plan hobbyist --cloud google-europe-west1
```

### Terminate safely
```
avn service terminate --dry-run myservice --project myproject
avn service terminate --force myservice --project myproject
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Command failed (check JSON error on stdout) |
| 2    | Interrupted (SIGINT) |
| 13   | Output truncated (SIGPIPE) |

## Invariants

- Resource names (service, topic, index) must not contain: `..`, `?`, `#`, `%XX`, or control characters.
- All API calls go to `AIVEN_WEB_URL` (default: `https://api.aiven.io`).
- The CLI URL-encodes all path segments via `urllib.parse.quote(safe="")`.
```

**Step 2: Commit**

```
docs: add AGENTS.md with agent-facing CLI documentation

Structured guide for AI agents covering authentication, output
behavior, destructive command safety, common workflows, and
input invariants.
```

---

## Phase 6: Verification

### Task 8: Run full test suite, linting, and type checking

Verify everything works together.

**Step 1: Run the full validation pipeline**

Run: `make all`

This runs: install, validate-style (isort + black), lint (ruff + flake8 + mypy), test (pytest)

**Step 2: Fix any issues found**

If style issues: run `make reformat` (black + isort)
If type issues: add type annotations to new code
If test failures: investigate and fix

**Step 3: Run tests on the new files specifically**

Run: `python -m pytest tests/test_argx.py tests/test_cliarg.py tests/test_validation.py -v`
Expected: ALL PASS

**Step 4: Commit any fixes**

```
chore: fix lint/type/style issues from agent-ready changes
```

---

## Scoring Summary

| Axis | Before | After | Change |
|------|--------|-------|--------|
| Machine-Readable Output | 1 | 2 | Auto-JSON in pipes + structured errors |
| Raw Payload Input | 1 | 1 | No change (future work) |
| Schema Introspection | 0 | 0 | No change (future work) |
| Context Window Discipline | 0 | 1 | `--fields` filtering |
| Input Hardening | 0 | 1 | Resource ID validation |
| Safety Rails | 0 | 1 | `--dry-run` on destructive commands |
| Agent Knowledge Packaging | 0 | 1 | `AGENTS.md` |
| **Total** | **2** | **7** | **+5** |

**Rating: Human-only (2) → Agent-tolerant (7)**

---

## Future Work (not in this plan)

These would push the score higher but require larger architectural changes:

- **Schema introspection** (`avn schema <cmd>` returning argparse metadata as JSON) — Score +1-2
- **Raw JSON payload input** (`--payload @file` on all mutating commands) — Score +1
- **NDJSON streaming** for paginated results — Score +1
- **`--dry-run` on ALL mutating commands** (not just destructive) — Score +1
- **Response sanitization** against prompt injection — Score +1
- **Skill files** (YAML frontmatter + Markdown per command surface) — Score +1

These are tracked as future phases and would bring the score to 11-14 (Agent-ready).
