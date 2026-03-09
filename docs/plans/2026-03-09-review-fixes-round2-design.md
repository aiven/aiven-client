# Review Fixes Round 2 — Design

> **Context:** Fixes from Python code review and security review of PR #1 on jasamkos/aiven-client (branch `feat/agent-ready-cli`). Includes legitimate security findings, pre-existing code quality issues, and cosmetic improvements.

## Findings Addressed

| # | Finding | Source | Category |
|---|---------|--------|----------|
| 1 | Unicode normalization bypass in `validation.py` | Security reviewer | Defense-in-depth |
| 2 | PLR0912 complexity in `print_response` (pre-existing) | Python reviewer | Code quality |
| 3 | Missing test for multi-service dry-run terminate | Python reviewer | Test coverage |
| 4 | `output` variable naming in argx.py | Python reviewer | Readability |
| 5 | Missing validation on `service__list` service_name arg | Python reviewer | Consistency |
| 6 | Missing docstring on `validated_resource_id` | Python reviewer | Documentation |
| 7 | Dry-run test assertion too loose (`or` condition) | Python reviewer | Test quality |
| 8 | No warning when `--fields` references non-existent fields | Python reviewer | UX |
| 9 | `.format()` vs f-string inconsistency in dry-run messages | Python reviewer | Style |
| 10 | Regex comment for control char range | Python reviewer | Documentation |

## Task Grouping

**Task 1: Unicode NFKC normalization + validation docs** (items 1, 6, 10)
- Add `unicodedata.normalize('NFKC', value)` at top of `validate_resource_id()`
- Add tests for fullwidth Unicode bypass characters
- Add docstring to `validated_resource_id` factory function
- Add inline comment on control char regex

**Task 2: Extract format determination from `print_response`** (items 2, 4)
- Extract auto-JSON detection + format selection into `_determine_output_format()` helper
- Fixes pre-existing PLR0912 complexity warning
- Rename `output` to `json_data` in the json branch

**Task 3: Add missing validation to `service__list`** (item 5)
- Add `type=validated_resource_id("service_name")` to inline `@arg` on `service__list`
- Scan for other inline service_name args missing validation

**Task 4: Improve test quality and coverage** (items 3, 7)
- Add multi-service dry-run terminate test
- Tighten dry-run assertion to match exact output string
- Add `--fields` with non-existent field name test

**Task 5: Add `--fields` non-existent field warning** (item 8)
- Add `logging.warning()` to `_apply_field_filter` when fields aren't in data
- Warning goes to stderr (doesn't interfere with JSON on stdout for agents)
- Add test verifying warning is emitted

**Task 6: Modernize dry-run messages to f-strings + lint/push** (item 9)
- Convert `.format()` in dry-run print statements to f-strings
- Run isort/black/ruff, commit lint fixes
- Push to jasamkos remote

## Decisions

- **Warning for missing --fields goes to stderr** — agents parse stdout JSON, humans see warnings in terminal
- **All fixes in one PR pass** — small isolated changes, splitting adds overhead for no benefit
- **NFKC normalization is defense-in-depth** — Aiven API rejects non-ASCII server-side, but we validate client-side anyway
