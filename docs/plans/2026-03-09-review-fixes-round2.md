# Review Fixes Round 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all findings from Python code review and security review of the agent-ready CLI PR — security hardening, code quality, test coverage, and cosmetic improvements.

**Architecture:** All fixes are isolated to the framework layer (`argx.py`, `validation.py`, `cliarg.py`, `cli.py`) and their tests. No new files needed. Each task is independently testable.

**Tech Stack:** Python 3.9+, argparse, pytest, unittest.mock

**Branch:** `feat/agent-ready-cli` (continue on existing branch, push to `jasamkos` remote)

**Test runner:** `.venv/bin/python -m pytest`

---

## Task 1: Unicode NFKC normalization + validation docs

Fullwidth Unicode characters like `\uff0e` (fullwidth period) normalize to `.` after NFKC processing, which could bypass the `..` path traversal check. Add normalization before validation. Also improve documentation on the validation functions.

**Files:**
- Modify: `aiven/client/validation.py`
- Modify: `aiven/client/cliarg.py:24` (docstring only)
- Test: `tests/test_validation.py`

**Step 1: Write the failing tests**

Add to `tests/test_validation.py` inside the existing `TestValidateResourceId` class. Add these to the `test_rejects_dangerous_ids` parametrize list:

```python
("\uff0e\uff0e/etc/passwd", "fullwidth period path traversal"),
("service\uff1fadmin=true", "fullwidth question mark"),
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_validation.py -v`
Expected: 2 FAIL — fullwidth characters bypass the current checks

**Step 3: Write minimal implementation**

In `aiven/client/validation.py`, add `import unicodedata` and normalize at the top of `validate_resource_id`. Replace:

```python
import re
```

With:

```python
import re
import unicodedata
```

Then in `validate_resource_id`, add normalization as the first operation after the empty check. Replace:

```python
    if not value or not value.strip():
        raise ValueError(f"Invalid resource identifier for {field_name!r}: must not be empty")

    if ".." in value:
```

With:

```python
    if not value or not value.strip():
        raise ValueError(f"Invalid resource identifier for {field_name!r}: must not be empty")

    # Normalize Unicode to catch fullwidth character bypasses (e.g. ．．/ -> ../)
    value = unicodedata.normalize("NFKC", value)

    if ".." in value:
```

**Step 4: Add docstring to `validated_resource_id` in cliarg.py**

In `aiven/client/cliarg.py`, replace:

```python
def validated_resource_id(field_name: str) -> Callable[[str], str]:
    """Return an argparse type function that validates resource IDs."""
```

With:

```python
def validated_resource_id(field_name: str) -> Callable[[str], str]:
    """Return an argparse ``type`` function that validates resource identifiers.

    Rejects common LLM hallucination patterns: path traversal, percent-encoding,
    query parameters, fragments, control characters, and fullwidth Unicode bypasses.

    Args:
        field_name: Name of the CLI argument (used in error messages).

    Returns:
        A validation function suitable for argparse's ``type`` parameter.
    """
```

**Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_validation.py tests/test_cliarg.py -v`
Expected: ALL PASS

**Step 6: Commit**

```
fix: add Unicode NFKC normalization to resource ID validation

Fullwidth Unicode characters (e.g. U+FF0E fullwidth period) can bypass
the path traversal check. Normalizing to NFKC before validation closes
this defense-in-depth gap.
```

---

## Task 2: Extract format determination from `print_response`

The `print_response` method has 13 branches (PLR0912 limit is 12). Extract the auto-JSON detection and format selection logic into a helper. Also rename the `output` variable to `json_data` for clarity.

**Files:**
- Modify: `aiven/client/argx.py:334-402`
- Test: `tests/test_argx.py` (existing tests serve as regression — no new tests needed)

**Step 1: Run existing tests to confirm baseline**

Run: `.venv/bin/python -m pytest tests/test_argx.py -v`
Expected: ALL PASS (18 tests)

**Step 2: Extract `_should_emit_json` helper and rename variable**

In `aiven/client/argx.py`, add a new method before `print_response` (after `_apply_field_filter`, around line 333). Insert:

```python
    def _should_emit_json(self, json: bool, csv: bool, format: str | None, file: TextIO) -> bool:
        """Determine whether output should be JSON.

        Returns True if json=True explicitly, or if auto-JSON detection
        triggers (non-TTY output, no --no-auto-json, no csv, no format).
        """
        if json:
            return True
        if csv or format is not None:
            return False
        if getattr(self.args, "no_auto_json", False):
            return False
        return hasattr(file, "isatty") and not file.isatty()
```

Then simplify `print_response`. Replace the entire method body (lines 346-402):

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

        json = self._should_emit_json(json, csv, format, file)

        # Convert to collection for all output paths
        result_collection = self._to_mapping_collection(result, single_item=single_item)

        # format= uses raw data (field filtering does not apply)
        if format is not None:
            for item in result_collection:
                print(format.format(**item), file=file)
            return

        # Apply field filtering for json/csv/table output
        result_collection = self._apply_field_filter(result_collection)

        if json:
            json_data: Any = list(result_collection)
            if single_item and len(json_data) == 1:
                json_data = json_data[0]
            print(
                jsonlib.dumps(json_data, indent=4, sort_keys=True, cls=pretty.CustomJsonEncoder),
                file=file,
            )
        elif csv:
            fields = []
            assert table_layout is not None
            for field in table_layout:
                if isinstance(field, str):
                    fields.append(field)
                else:
                    fields.extend(field)

            writer = csvlib.DictWriter(file, extrasaction="ignore", fieldnames=fields)
            if header:
                writer.writeheader()
            for item in result_collection:
                writer.writerow(item)
        else:
            pretty.print_table(
                result_collection,
                drop_fields=drop_fields,
                table_layout=table_layout,
                header=header,
                file=file,
            )
```

**Step 3: Run tests to verify no regressions**

Run: `.venv/bin/python -m pytest tests/test_argx.py -v`
Expected: ALL PASS (18 tests)

**Step 4: Verify PLR0912 is resolved**

Run: `.venv/bin/python -m ruff check aiven/client/argx.py --select PLR0912`
Expected: No errors (branch count reduced from 13 to within limit)

**Step 5: Commit**

```
refactor: extract _should_emit_json to reduce print_response complexity

Resolves pre-existing PLR0912 (too many branches) ruff warning.
Also renames output variable to json_data for clarity.
```

---

## Task 3: Add missing validation to `service__list`

The `service__list` command uses an inline `@arg("service_name", nargs="*")` without the `validated_resource_id` type. Add it for consistency with `service__terminate`.

**Files:**
- Modify: `aiven/client/cli.py:914`
- Test: `tests/test_cli.py`

**Step 1: Write the failing test**

Add to `tests/test_cli.py` inside the existing `TestResourceIdValidation` class:

```python
    def test_service_list_rejects_path_traversal(self) -> None:
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            with pytest.raises(SystemExit) as exc_info:
                cli.run(args=["service", "list", "../etc/passwd"])
            assert exc_info.value.code == EXIT_CODE_INVALID_USAGE
        aiven_client.get_services.assert_not_called()
```

**Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestResourceIdValidation::test_service_list_rejects_path_traversal -v`
Expected: FAIL — `../etc/passwd` is accepted (no validation on inline arg)

**Step 3: Write minimal implementation**

In `aiven/client/cli.py`, replace line 914:

```python
    @arg("service_name", nargs="*", default=[], help="Service name")
```

With:

```python
    @arg("service_name", nargs="*", default=[], help="Service name", type=validated_resource_id("service_name"))
```

**Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestResourceIdValidation -v`
Expected: ALL PASS (2 tests)

**Step 5: Commit**

```
fix: add resource ID validation to service list inline arg

service__list uses its own @arg("service_name", nargs="*") without
the validated_resource_id type. Add it for consistency with other
service commands.
```

---

## Task 4: Improve test quality and coverage

Tighten loose assertions and add missing edge case tests.

**Files:**
- Test: `tests/test_cli.py`
- Test: `tests/test_argx.py`

**Step 1: Tighten dry-run assertion**

In `tests/test_cli.py`, replace the loose assertion in `test_service_terminate_dry_run` (line 3015):

```python
        assert "dry-run" in captured.out.lower() or "dry_run" in captured.out.lower()
```

With the exact expected output:

```python
        assert "dry-run: would terminate service 'my-service' in project 'myproject'" in captured.out
```

**Step 2: Add multi-service dry-run test**

Add to `tests/test_cli.py` inside the `TestDryRun` class, after `test_service_terminate_dry_run`:

```python
    def test_service_terminate_dry_run_multiple(self, capsys: CaptureFixture[str]) -> None:
        aiven_client = mock.Mock(spec_set=AivenClient)
        cli = build_aiven_cli(aiven_client)
        with mock_config({"default_project": "myproject"}):
            result = cli.run(args=["service", "terminate", "--force", "--dry-run", "svc1", "svc2"])
        assert result is None
        aiven_client.delete_service.assert_not_called()
        captured = capsys.readouterr()
        assert "svc1" in captured.out
        assert "svc2" in captured.out
```

**Step 3: Add `--fields` with non-existent field test**

Add to `tests/test_argx.py` inside the `TestFieldsFiltering` class:

```python
    def test_fields_nonexistent_warns(self) -> None:
        """--fields with a non-existent field should warn and return empty keys."""
        tool = self._make_tool(fields="nonexistent")
        tool.log = mock.Mock()
        buf = io.StringIO()
        buf.isatty = lambda: True  # type: ignore[assignment]
        tool.print_response(
            [{"name": "svc1", "plan": "hobby"}],
            json=True,
            file=buf,
        )
        parsed = json.loads(buf.getvalue())
        assert parsed == [{}]
        tool.log.warning.assert_called_once()
```

Note: This test will fail until Task 5 adds the warning logic. That's expected — write it now, it becomes green in Task 5.

**Step 4: Run the tests that should pass now**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestDryRun tests/test_cli.py::TestResourceIdValidation -v`
Expected: ALL PASS (6 tests now)

**Step 5: Commit**

```
test: tighten dry-run assertions and add multi-service test

Exact output matching replaces loose substring checks. Adds test for
terminating multiple services with --dry-run. Adds pending test for
--fields warning (will pass after field warning is implemented).
```

---

## Task 5: Add `--fields` non-existent field warning

When `--fields` references field names not present in the data, emit a warning to stderr via `self.log.warning()`. This helps both humans and agents understand why output is empty.

**Files:**
- Modify: `aiven/client/argx.py:326-332` (`_apply_field_filter` method)
- Test: `tests/test_argx.py` (test written in Task 4)

**Step 1: Write the implementation**

In `aiven/client/argx.py`, replace the `_apply_field_filter` method:

```python
    def _apply_field_filter(self, result: Collection[Mapping[str, Any]]) -> Collection[Mapping[str, Any]]:
        """Filter result dicts to only include requested fields."""
        fields_str = getattr(self.args, "fields", None)
        if not fields_str:
            return result
        fields = {f.strip() for f in fields_str.split(",")}
        return [{k: v for k, v in item.items() if k in fields} for item in result]
```

With:

```python
    def _apply_field_filter(self, result: Collection[Mapping[str, Any]]) -> Collection[Mapping[str, Any]]:
        """Filter result dicts to only include requested fields."""
        fields_str = getattr(self.args, "fields", None)
        if not fields_str:
            return result
        fields = {f.strip() for f in fields_str.split(",")}
        result_list = list(result)
        if result_list:
            available = set(result_list[0].keys())
            missing = fields - available
            if missing:
                self.log.warning("--fields: requested fields not found in data: %s", ", ".join(sorted(missing)))
        return [{k: v for k, v in item.items() if k in fields} for item in result_list]
```

**Step 2: Run the test from Task 4 to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_argx.py::TestFieldsFiltering::test_fields_nonexistent_warns -v`
Expected: PASS

**Step 3: Run all argx tests for regression**

Run: `.venv/bin/python -m pytest tests/test_argx.py -v`
Expected: ALL PASS (19 tests)

**Step 4: Commit**

```
feat: warn when --fields references non-existent field names

Emits a warning to stderr when requested fields are not found in
the result data. Helps users and agents understand why output may
be empty. Warning goes to stderr so it does not interfere with
JSON output on stdout.
```

---

## Task 6: Modernize dry-run messages to f-strings + lint/push

Convert `.format()` calls in dry-run print statements to f-strings for consistency with the rest of the codebase.

**Files:**
- Modify: `aiven/client/cli.py` (3 lines)
- Run: isort, black, ruff

**Step 1: Convert format strings**

In `aiven/client/cli.py`, make these three replacements:

Line 3634 — replace:
```python
                print("dry-run: would terminate service {!r} in project {!r}".format(name, self.get_project()))
```
With:
```python
                print(f"dry-run: would terminate service {name!r} in project {self.get_project()!r}")
```

Line 4404 — replace:
```python
            print("dry-run: would delete project {!r}".format(self.args.project_name))
```
With:
```python
            print(f"dry-run: would delete project {self.args.project_name!r}")
```

Line 6109 — replace:
```python
            print("dry-run: would delete organization {!r}".format(self.args.organization_id))
```
With:
```python
            print(f"dry-run: would delete organization {self.args.organization_id!r}")
```

**Step 2: Run dry-run tests to verify no regressions**

Run: `.venv/bin/python -m pytest tests/test_cli.py::TestDryRun -v`
Expected: ALL PASS

**Step 3: Run formatting and linting**

Run: `.venv/bin/python -m isort aiven tests && .venv/bin/python -m black aiven tests`
Run: `.venv/bin/python -m ruff check aiven tests`

Fix any issues found. The only expected pre-existing ruff error is the `F841` unused variable in `test_service_terminate_without_dry_run` — that's not our code.

**Step 4: Run all new and modified tests together**

Run: `.venv/bin/python -m pytest tests/test_argx.py tests/test_cliarg.py tests/test_validation.py tests/test_cli.py::TestDryRun tests/test_cli.py::TestResourceIdValidation -v`
Expected: ALL PASS

**Step 5: Commit lint/style fixes if any**

```
chore: modernize dry-run messages to f-strings and fix lint
```

**Step 6: Push to jasamkos remote**

Run: `git push jasamkos feat/agent-ready-cli`

This updates PR #1 with all review fixes round 2.

---

## Summary

| Task | Findings Addressed | Type |
|------|--------------------|------|
| 1 | Unicode bypass + docstring + regex comment | Security + Docs |
| 2 | PLR0912 complexity + variable naming | Code quality |
| 3 | Missing validation on service__list | Consistency |
| 4 | Loose assertions + multi-service test + fields test | Test quality |
| 5 | Warning for non-existent --fields | UX |
| 6 | f-string modernization + lint/push | Style |
