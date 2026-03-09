# Agent-Ready CLI Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the 2 critical issues and 2 important issues found in the code review of PR #1 on jasamkos/aiven-client (branch `feat/agent-ready-cli`).

**Architecture:** All fixes are isolated to the framework layer (`argx.py`, `cliarg.py`, `cli.py`) and their tests. No new files needed. Each fix is independently testable.

**Tech Stack:** Python 3.9+, argparse, pytest, unittest.mock

**Branch:** `feat/agent-ready-cli` (continue on existing branch, push to `jasamkos` remote)

**Test runner:** `.venv/bin/python -m pytest`

**Context:** This plan addresses review findings from PR https://github.com/jasamkos/aiven-client/pull/1. The PR adds agent-readiness features (auto-JSON, structured errors, `--fields`, `--dry-run`, resource ID validation, AGENTS.md). The review found issues with the refactored `print_response` method and missing validation/test coverage.

---

## Task 1: Fix JSON output shape regression for `single_item=True`

The refactored `print_response` converts all results to a collection early (for `--fields` filtering), which means `single_item=True` with `json=True` now emits `[{...}]` instead of `{...}`. This breaks existing scripts that parse `avn service get --json`.

**Files:**
- Modify: `aiven/client/argx.py:334-394` (print_response method)
- Test: `tests/test_argx.py`

**Step 1: Write the failing test**

Add to `tests/test_argx.py` inside the existing `TestFieldsFiltering` class (after `test_fields_single_item`):

```python
def test_single_item_json_emits_object_not_array(self) -> None:
    """single_item=True with json=True must emit {}, not [{}]."""
    tool = self._make_tool(fields=None)
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[assignment]
    tool.print_response(
        {"name": "svc1", "plan": "hobby"},
        json=True,
        single_item=True,
        file=buf,
    )
    parsed = json.loads(buf.getvalue())
    # Must be a dict, not a list
    assert isinstance(parsed, dict)
    assert parsed == {"name": "svc1", "plan": "hobby"}

def test_single_item_json_with_fields_emits_object(self) -> None:
    """single_item=True + json=True + --fields must emit filtered {}."""
    tool = self._make_tool(fields="name")
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[assignment]
    tool.print_response(
        {"name": "svc1", "plan": "hobby"},
        json=True,
        single_item=True,
        file=buf,
    )
    parsed = json.loads(buf.getvalue())
    assert isinstance(parsed, dict)
    assert parsed == {"name": "svc1"}
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_argx.py::TestFieldsFiltering::test_single_item_json_emits_object_not_array tests/test_argx.py::TestFieldsFiltering::test_single_item_json_with_fields_emits_object -v`
Expected: FAIL — `isinstance(parsed, dict)` fails because it's a list

**Step 3: Write minimal implementation**

In `aiven/client/argx.py`, modify the `json` branch of `print_response` (around line 368-372). Replace:

```python
        elif json:
            print(
                jsonlib.dumps(list(result_collection), indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder),
                file=file,
            )
```

With:

```python
        elif json:
            output: Any = list(result_collection)
            if single_item and len(output) == 1:
                output = output[0]
            print(
                jsonlib.dumps(output, indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder),
                file=file,
            )
```

**Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_argx.py -v`
Expected: ALL PASS (17 tests)

**Step 5: Commit**

```
fix: preserve single-item JSON output shape for backward compatibility

When single_item=True and json=True, emit a JSON object {...} instead
of an array [{...}]. This restores the original behavior that existing
scripts and avn service get --json consumers depend on.
```

---

## Task 2: Fix `--fields` + `format=` interaction causing KeyError

When both `--fields` and `format=` are provided, field filtering removes keys before the format string tries to reference them, causing a KeyError. The `format` branch should use the unfiltered result.

**Files:**
- Modify: `aiven/client/argx.py:334-394` (print_response method)
- Test: `tests/test_argx.py`

**Step 1: Write the failing test**

Add to `tests/test_argx.py` inside the existing `TestFieldsFiltering` class:

```python
def test_fields_does_not_break_format_string(self) -> None:
    """--fields should not filter when format= is used."""
    tool = self._make_tool(fields="name")
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[assignment]
    # format references 'plan' which is NOT in --fields
    tool.print_response(
        [{"name": "svc1", "plan": "hobby"}],
        json=False,
        format="{name} {plan}",
        file=buf,
    )
    assert buf.getvalue().strip() == "svc1 hobby"
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_argx.py::TestFieldsFiltering::test_fields_does_not_break_format_string -v`
Expected: FAIL — KeyError on 'plan'

**Step 3: Write minimal implementation**

In `aiven/client/argx.py`, modify `print_response` so the `format` branch uses the unfiltered collection. Move the `format` check before field filtering. Replace this block (around lines 361-367):

```python
        # Apply field filtering if --fields was provided
        result_collection = self._to_mapping_collection(result, single_item=single_item)
        result_collection = self._apply_field_filter(result_collection)

        if format is not None:
            for item in result_collection:
                print(format.format(**item), file=file)
```

With:

```python
        # Convert to collection for all output paths
        result_collection = self._to_mapping_collection(result, single_item=single_item)

        # format= uses raw data (field filtering does not apply)
        if format is not None:
            for item in result_collection:
                print(format.format(**item), file=file)
            return

        # Apply field filtering for json/csv/table output
        result_collection = self._apply_field_filter(result_collection)
```

Also change the `elif json:` to `if json:` since format now returns early:

```python
        if json:
```

And change `elif csv:` stays as `elif csv:` (no change needed there).

**Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_argx.py -v`
Expected: ALL PASS (18 tests)

**Step 5: Commit**

```
fix: skip --fields filtering when format= string is used

format= references arbitrary keys, so field filtering must not
remove keys that the format string needs. format= now returns
early before filtering is applied.
```

---

## Task 3: Add resource ID validation to `service__terminate` inline arg

The `service__terminate` command declares its own `@arg("service_name", nargs="+")` instead of using `@arg.service_name`, so the `type=validated_resource_id()` from `cliarg.py` doesn't apply. This is the most dangerous command and should validate.

Also add validation to `arg.service_name_mandatory` in `cliarg.py`.

**Files:**
- Modify: `aiven/client/cli.py:3629` (service__terminate arg decorator)
- Modify: `aiven/client/cliarg.py:204` (service_name_mandatory)
- Test: `tests/test_cli.py`

**Step 1: Write the failing test**

Add to `tests/test_cli.py` inside the existing `TestDryRun` class (or create a new class `TestResourceIdValidation`):

```python
class TestResourceIdValidation:
    """Resource ID validation should reject dangerous names."""

    def test_service_terminate_rejects_path_traversal(self) -> None:
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            result = cli.run(args=["service", "terminate", "--force", "../etc/passwd"])
        # argparse exits with code 2 for invalid args
        assert result == 2 or result is not None
        aiven_client.delete_service.assert_not_called()
```

Note: argparse calls `sys.exit(2)` for type validation failures. The `CommandLineTool.run` method doesn't catch `SystemExit`, so this will actually raise `SystemExit(2)`. Use `pytest.raises(SystemExit)`:

```python
class TestResourceIdValidation:
    """Resource ID validation should reject dangerous names."""

    def test_service_terminate_rejects_path_traversal(self) -> None:
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            with pytest.raises(SystemExit) as exc_info:
                cli.run(args=["service", "terminate", "--force", "../etc/passwd"])
            assert exc_info.value.code == EXIT_CODE_INVALID_USAGE
        aiven_client.delete_service.assert_not_called()
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestResourceIdValidation -v`
Expected: FAIL — `../etc/passwd` is accepted (no validation on inline arg)

**Step 3: Write minimal implementation**

In `aiven/client/cli.py`, find the `service__terminate` decorator (line 3629):

```python
    @arg("service_name", help="Service name", nargs="+")
```

Change to:

```python
    @arg("service_name", help="Service name", nargs="+", type=cliarg.validated_resource_id("service_name"))
```

This requires `cliarg` to be imported. Check the existing imports at the top of `cli.py`:

```python
from aiven.client import cliarg
```

If this import doesn't exist, look for how `cliarg` symbols are accessed. The file uses `from aiven.client.cliarg import arg` — so add `validated_resource_id` to that import, or use `cliarg.validated_resource_id`. Check the actual import line and adjust accordingly.

Also in `aiven/client/cliarg.py`, update `arg.service_name_mandatory` (line 204):

```python
arg.service_name_mandatory = arg("service_name", help="Service name", required=True, type=validated_resource_id("service_name"))
```

**Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestResourceIdValidation -v`
Expected: PASS

**Step 5: Run broader test suite to check for regressions**

Run: `.venv/bin/python -m pytest tests/test_argx.py tests/test_cliarg.py tests/test_validation.py tests/test_cli.py::TestDryRun tests/test_cli.py::TestResourceIdValidation -v`
Expected: ALL PASS

**Step 6: Commit**

```
fix: add resource ID validation to service terminate inline arg

service__terminate uses its own @arg("service_name", nargs="+")
instead of @arg.service_name, so the validation type was missing.
Also adds validation to arg.service_name_mandatory.
```

---

## Task 4: Add missing test for `organization delete --dry-run`

**Files:**
- Test: `tests/test_cli.py`

**Step 1: Write the test**

Add to `tests/test_cli.py` inside the existing `TestDryRun` class:

```python
    def test_organization_delete_dry_run(self, capsys: CaptureFixture[str]) -> None:
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({}):
            result = cli.run(args=["organization", "delete", "--force", "--dry-run", "org-12345"])
        assert result is None
        aiven_client.delete_organization.assert_not_called()
        captured = capsys.readouterr()
        assert "org-12345" in captured.out
        assert "dry-run" in captured.out.lower()
```

**Step 2: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestDryRun -v`
Expected: ALL PASS (4 tests now)

**Step 3: Commit**

```
test: add missing organization delete --dry-run test
```

---

## Task 5: Run full linting and push

**Step 1: Run formatting**

Run: `.venv/bin/python -m isort aiven tests && .venv/bin/python -m black aiven tests`

**Step 2: Run linting**

Run: `.venv/bin/python -m ruff check aiven tests && .venv/bin/python -m flake8 aiven tests`

Fix any issues found.

**Step 3: Run all new tests together**

Run: `.venv/bin/python -m pytest tests/test_argx.py tests/test_cliarg.py tests/test_validation.py tests/test_cli.py::TestDryRun tests/test_cli.py::TestResourceIdValidation -v`
Expected: ALL PASS

**Step 4: Commit any lint fixes**

```
chore: fix lint/style issues from review fixes
```

**Step 5: Push to jasamkos remote**

Run: `git push jasamkos feat/agent-ready-cli`

This updates PR #1 with the review fixes.

---

## Review Fix Summary

| Issue | Severity | Fix |
|-------|----------|-----|
| `single_item=True` JSON emits `[{...}]` instead of `{...}` | CRITICAL | Unwrap single-element list in json branch |
| `--fields` + `format=` causes KeyError | IMPORTANT | Move `format` branch before field filtering, return early |
| `service__terminate` bypasses validation | CRITICAL | Add `type=validated_resource_id()` to inline `@arg` |
| No test for `organization delete --dry-run` | IMPORTANT | Add test |

**Note:** The review flagged `organization__delete --force` not skipping `self.confirm()` as a bug, but `self.confirm()` already checks `self.args.force` internally (returns `True` when force is set). This is NOT a bug — no fix needed.
