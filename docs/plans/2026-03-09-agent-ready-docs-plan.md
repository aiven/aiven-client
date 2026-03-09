# Agent-Ready Documentation & Skills — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create 18 skill files, expand AGENTS.md, create CLAUDE.md, and convert README.rst to README.md — making aiven-client fully discoverable by AI agents while preserving all existing human documentation content.

**Design:** See `docs/plans/2026-03-09-agent-ready-docs-design.md`

**Architecture:** All changes are documentation-only. No code changes. No CI/CD changes.

**Critical constraint:** README.md must preserve all human-facing content from README.rst. The RST→Markdown conversion must be faithful — no information loss.

---

## Phase 1: Shared Skill

### Task 1: Create `skills/avn-shared/SKILL.md`

The foundation skill that all other skills reference. Must be self-contained — an agent reading only this file can use `avn` safely.

**Create:** `skills/avn-shared/SKILL.md`

```markdown
---
name: avn-shared
version: 1.0.0
description: "avn CLI: Shared patterns for authentication, global flags, output formatting, and safety."
metadata:
  requires:
    bins: ["avn"]
---

# avn — Shared Reference

## Installation

```bash
# Install from PyPI
python3 -m pip install aiven-client

# Or run without installing
uvx --from aiven-client avn --help
```

## Authentication

```bash
# Interactive login
avn user login <you@example.com>

# Token-based (for agents and CI)
export AIVEN_AUTH_TOKEN=<your-token>

# Create a token
avn user access-token create --description "agent" --json
```

**Credential files** (alternative to env vars):
- `~/.config/aiven/aiven-credentials.json` — `{"auth_token": "...", "user_email": "..."}`
- `~/.config/aiven/aiven-client.json` — `{"default_project": "..."}`

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AIVEN_AUTH_TOKEN` | API authentication token | — |
| `AIVEN_PROJECT` | Default project for all commands | — |
| `AIVEN_WEB_URL` | API base URL | `https://api.aiven.io` |
| `AIVEN_FORCE` | Set to `true` to skip confirmations | — |

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Force JSON output |
| `--no-auto-json` | Disable automatic JSON in non-TTY contexts |
| `--fields <f1,f2,...>` | Comma-separated list of fields to include in output |
| `--format <string>` | Custom format string (e.g. `{service_name}: {state}`) |
| `--project <name>` | Target project (overrides env/config) |
| `--dry-run` | Show what would be done without executing (destructive commands) |
| `--force` | Skip interactive confirmation prompts |

## CLI Syntax

```bash
avn <group> <subcommand> [flags] [positional-args]
```

Groups use space-separated names: `avn service list`, `avn billing-group create`, `avn user access-token list`.

## Output Behavior

- **Non-TTY (piped) contexts** automatically emit JSON — no `--json` flag needed.
- Force table output in pipes with `--no-auto-json`.
- Errors in non-TTY contexts are JSON on stdout: `{"error": true, "message": "...", "exit_code": 1}`
- Use `--fields` to reduce output size and token usage.
- Discover available field names: `avn <command> --json | head -1`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Command failed (check JSON error on stdout in non-TTY) |
| 2 | Invalid usage / interrupted (SIGINT) |
| 13 | Output truncated (SIGPIPE) |

## Safety Rules

- **Always** use `--dry-run` before destructive operations (`terminate`, `delete`).
- **Always** use `--force` to skip interactive prompts in automated contexts.
- **Never** output secrets (tokens, passwords) to logs or shared channels.
- Prefer `--fields` to limit output to what you need.

## Input Invariants

Resource names (service, topic, index, database) must not contain:
- Path traversal: `..`
- Query parameters: `?`
- Fragments: `#`
- Percent-encoded sequences: `%XX`
- Control characters: null bytes, newlines, tabs

All API path segments are URL-encoded via `urllib.parse.quote(safe="")`.
```

**Verify:** File is valid Markdown with YAML frontmatter. All flags mentioned actually exist in the codebase.

**Commit:**

```
docs: add shared skill (avn-shared) with auth, flags, output, and safety reference
```

---

## Phase 2: Per-Service Skills

### Task 2: Create all 17 per-service skill files

Create each skill following the template established in the design. Each skill has: frontmatter, title, prerequisites reference, subcommands table, common workflows, and gotchas.

Below are the files to create. Each file follows this skeleton:

```markdown
---
name: avn-<group>
version: 1.0.0
description: "<one-liner>"
metadata:
  requires:
    bins: ["avn"]
---

# <group>

<one-liner description>

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn <group> <sub>` | ... |

## Common Workflows

### <workflow title>
```bash
avn <group> <sub> --project myproject --fields <relevant>
```

## Gotchas

- <pitfall that --help won't tell you>
```

**Files to create:**

#### `skills/avn-service/SKILL.md` (~150 lines)
Core service lifecycle. Subcommands: `create`, `get`, `list`, `update`, `terminate`, `wait`, `types`, `plans`, `versions`, `logs`, `metrics`, `backup-list`, `cli`. Also covers: `database-create/delete/list`, `user-create/delete/list`, `user-creds-download`, `connection-pool-*`, `tags-*`, `connection-info-*`.

Workflows: Create and wait for service, get connection URI, power cycle, list with field filtering.

Gotchas: `terminate` requires `--force` in non-interactive mode. Service names are unique per project. `service list` without a name lists all services. `wait` polls until RUNNING. `--disk-space-gib` only for plans that support it.

#### `skills/avn-kafka/SKILL.md` (~130 lines)
Kafka-specific operations (all under `avn service`). Subcommands: `topic-create/delete/get/list/update`, `acl-add/delete/list`, `kafka-acl-add/delete/list`, `schema-*` (Schema Registry), `connector-*`, `schema-registry-acl-*`.

Workflows: Create topic with retention, manage ACLs, deploy connector, register schema.

Gotchas: Two ACL systems — Aiven ACL (`acl-*`) and Kafka-native ACL (`kafka-acl-*`). `--partitions` and `--replication` are required for topic creation. Schema Registry uses `--subject` not `--topic`. Connector config is JSON via `-c` or `--connector-config`.

#### `skills/avn-project/SKILL.md` (~80 lines)
Subcommands: `create`, `delete`, `details`, `list`, `switch`, `update`, `ca-get`, `tags-*`, `user-invite/list/remove`, `invite-list`, `generate-sbom`.

Workflows: Create project, invite user, switch active project.

Gotchas: `--parent-id` (organization ID) is required for `create`. `delete` is irreversible. `switch` changes the local default, not a server-side setting.

#### `skills/avn-user/SKILL.md` (~70 lines)
Subcommands: `login`, `logout`, `info`, `create`, `password-change`, `tokens-expire`, `access-token create/list/revoke/update`.

Workflows: Create access token for automation, rotate tokens.

Gotchas: `logout` only revokes current session token. `tokens-expire` revokes ALL tokens. `access-token create` returns the token only once — save it immediately.

#### `skills/avn-vpc/SKILL.md` (~70 lines)
Subcommands: `create`, `delete`, `list`, `peering-connection create/delete/get/list`, `user-peer-network-cidr add/delete`.

Workflows: Create VPC, set up peering connection.

Gotchas: `--cloud` and `--network-cidr` are required for `create`. VPC deletion fails if services are still attached. Peering connections require peer account/VPC/region.

#### `skills/avn-cloud/SKILL.md` (~40 lines)
Single subcommand: `list`. Lists available cloud regions.

Workflows: Find available regions, filter by provider.

Gotchas: Cloud names follow pattern `<provider>-<region>` (e.g., `google-europe-west1`, `aws-us-east-1`).

#### `skills/avn-account/SKILL.md` (~90 lines)
Subcommands: `create`, `delete`, `list`, `update`, `team *` (create/delete/list, user-invite/delete/list/list-pending, project-attach/detach/list), `oauth2-client *` (create/delete/get/list/update, redirect-*, secret-*).

Workflows: Create team, invite member, attach to project.

Gotchas: Team types are `admin`, `developer`, `operator`, `read_only`. OAuth2 client secrets are shown only at creation time.

#### `skills/avn-organization/SKILL.md` (~80 lines)
Subcommands: `create`, `delete`, `list`, `update`, `user invite/list`, `group *`, `card *`, `vpc *` (create/delete/get/list, peering-connection *, clouds list).

Workflows: Create organization, manage VPCs at org level.

Gotchas: Organization VPCs (`organization vpc`) are different from project VPCs (`vpc`). `--organization-id` is required for most operations.

#### `skills/avn-billing/SKILL.md` (~70 lines)
Covers `billing-group` commands: `create`, `delete`, `get`, `list`, `update`, `assign-projects`, `credits-claim/list`, `events`, `invoice-list/lines`.

Workflows: Create billing group, assign projects, claim credits.

Gotchas: Projects must be assigned to a billing group. `credits-claim` requires a credit code from Aiven.

#### `skills/avn-mirrormaker/SKILL.md` (~50 lines)
Subcommands: `replication-flow create/delete/get/list/update`.

Workflows: Create cross-cluster replication flow.

Gotchas: Requires a running MirrorMaker 2 service. Source and destination are Kafka service names.

#### `skills/avn-static-ip/SKILL.md` (~50 lines)
Subcommands: `create`, `delete`, `list`, `associate`, `dissociate`.

Workflows: Create and associate static IP with service.

Gotchas: Static IPs are cloud-specific. Must dissociate before deleting. Not all service types support static IPs.

#### `skills/avn-byoc/SKILL.md` (~60 lines)
Subcommands: `create`, `delete`, `list`, `provision`, `update`, `cloud permissions *`, `tags *`, `template terraform *`.

Workflows: Set up BYOC, download Terraform template.

Gotchas: BYOC requires organization-level access. Provisioning is async — check status after creation.

#### `skills/avn-permissions/SKILL.md` (~50 lines)
Subcommands: `list`, `set`.

Workflows: List permissions, set role for user on project.

Gotchas: `set` replaces all existing permissions for the resource/principal pair. `--resource-type` is one of `organization`, `organization_unit`, `project`.

#### `skills/avn-application-user/SKILL.md` (~60 lines)
Subcommands: `create`, `delete`, `info`, `list`, `update`, `token create/info/list/revoke`.

Workflows: Create application user, generate token.

Gotchas: Application users are organization-scoped. `--organization-id` is required. Tokens are shown only at creation.

#### `skills/avn-sustainability/SKILL.md` (~40 lines)
Subcommands: `project-emissions-estimate`, `service-plan-emissions-project`.

Workflows: Estimate project carbon footprint.

Gotchas: Emissions are estimates, not exact measurements.

#### `skills/avn-ticket/SKILL.md` (~40 lines)
Subcommands: `create`, `list`.

Workflows: Create support ticket, list open tickets.

Gotchas: Tickets are project-scoped. Severity and service name are useful for faster routing.

#### `skills/avn-events/SKILL.md` (~40 lines)
Command: `avn events` (no subcommands — it's a direct command).

Workflows: View recent project events.

Gotchas: Events are project-scoped. Uses `--project` flag. Shows management events (service creation, user changes), not service-level logs.

**Verify:** All 17 files created. All subcommand names match actual CLI methods. Cross-references to avn-shared are correct.

**Commit:**

```
docs: add per-service skills for all 17 command groups

Skills cover service, kafka, project, user, vpc, cloud, account,
organization, billing, mirrormaker, static-ip, byoc, permissions,
application-user, sustainability, ticket, and events.
```

---

## Phase 3: AGENTS.md Expansion

### Task 3: Expand AGENTS.md from 67 to ~220 lines

Read the existing AGENTS.md first. Preserve all current content but restructure and expand.

**Modify:** `AGENTS.md`

**New structure:**

1. **Header** — "# Agent Guide for aiven-client (`avn`)" (keep)
2. **Overview** — New: "Official CLI for Aiven cloud services — built for humans and AI agents."
3. **Quick Start** — New 5-line block:
   ```bash
   export AIVEN_AUTH_TOKEN=<token>
   export AIVEN_PROJECT=<project>
   avn service list --fields service_name,state,plan
   avn service get <name> --fields service_name,state,service_uri
   ```
4. **Authentication** — Expand existing: add credential file paths, token rotation advice
5. **Output Behavior** — Expand existing: add field discovery pattern
6. **Skills Directory** — New: table of all 18 skills with descriptions and paths
7. **Destructive Commands** — Expand existing: categorize by risk level:
   - Irreversible: `service terminate`, `project delete`, `organization delete`
   - Reversible but disruptive: `service update --power-off`, `service user-delete`
   - Data-modifying: `service topic-delete`, `service database-delete`, `service index-delete`
8. **Common Workflows** — Expand existing: add multi-step flows
9. **Exit Codes** — Keep as-is
10. **Input Invariants** — Keep as-is
11. **Rate Limits & Retries** — New: "The Aiven API has rate limits. On HTTP 429, wait and retry with exponential backoff. The CLI does not retry automatically."
12. **Environment Variables** — New: complete table (AIVEN_AUTH_TOKEN, AIVEN_PROJECT, AIVEN_WEB_URL, AIVEN_FORCE)

**Verify:** All skill paths in the skills directory table point to existing files. All command examples are valid.

**Commit:**

```
docs: expand AGENTS.md with skills directory, risk categories, and env var reference
```

---

## Phase 4: CLAUDE.md

### Task 4: Create CLAUDE.md

Comprehensive agent-as-developer guide. ~250 lines.

**Create:** `CLAUDE.md`

**Content outline (write the full file):**

```markdown
# Contributing to aiven-client

When contributing to this repository, follow the guidelines below and in AGENTS.md.

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
| `aiven/client/cli.py` | All CLI command methods (~4000 lines, single file) |
| `aiven/client/argx.py` | Base CLI framework: argument parsing, `print_response`, error handling |
| `aiven/client/cliarg.py` | Shared argument decorators (`@arg.project`, `@arg.force`, etc.) |
| `aiven/client/client.py` | REST API client — all HTTP calls to Aiven API |
| `aiven/client/pretty.py` | Table formatting and output helpers |
| `aiven/client/validation.py` | Resource ID validation (anti-hallucination) |
| `aiven/client/envdefault.py` | Environment variable defaults for arguments |
| `aiven/client/connection_info/` | Service-specific connection string builders |
| `tests/test_cli.py` | Main CLI test suite |
| `tests/test_argx.py` | Framework-level tests |
| `tests/test_cliarg.py` | Argument decorator tests |
| `tests/test_validation.py` | Resource ID validation tests |

## How to Add a New Command

1. **Naming:** Define a method in `cli.py` named `group__subcommand`. Double underscores map to spaces: `service__topic_create` → `avn service topic-create`. Single underscores become hyphens in the CLI.

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
       with mock_config({"default_project": "myproject"}):
           result = cli.run(args=["service", "my-command", "svc1"])
       assert result is None
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
- **Errors:** Raise `UserError("message")` for user-facing errors
- **Config:** `arg.project` uses `envdefault.AIVEN_PROJECT` for env var fallback

## Testing Patterns

```python
from aiven.client import AivenClient
from aiven.client.cli import AivenCLI
from unittest import mock

# Build CLI with mocked API client
def build_aiven_cli(client: AivenClient) -> AivenCLI:
    cli = AivenCLI(client_factory=mock.Mock(return_value=client))
    cli._get_auth_token = lambda *a, **kw: "mock-token"
    return cli

# Mock project config
@contextmanager
def mock_config(return_value):
    with mock.patch("aiven.client.argx.Config", side_effect=lambda _: return_value):
        yield

# Typical test
def test_example(capsys):
    aiven_client = mock.Mock(spec_set=AivenClient)
    aiven_client.some_method.return_value = [{"key": "value"}]
    cli = build_aiven_cli(aiven_client)
    with mock_config({"default_project": "proj"}):
        cli.run(args=["some", "command", "--project", "proj"])
    captured = capsys.readouterr()
    assert "value" in captured.out
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
```

**Verify:** All file paths in source layout exist. Code examples compile conceptually. Build commands match Makefile targets.

**Commit:**

```
docs: add CLAUDE.md agent-developer guide

Comprehensive guide covering source layout, how to add commands,
testing patterns, coding conventions, and agent-ready checklist.
```

---

## Phase 5: README Conversion

### Task 5: Convert README.rst to README.md

Read existing README.rst. Convert all RST syntax to Markdown. Restructure with agent-friendly additions. Delete README.rst.

**Delete:** `README.rst`
**Create:** `README.md`

**Conversion rules:**
- RST `::` code blocks → Markdown ``` fenced blocks
- RST `.. contents::` → Remove (GitHub auto-generates TOC)
- RST `*text*` → `*text*` (same in Markdown)
- RST `` ``code`` `` → `` `code` ``
- RST section underlines (`===`, `---`) → `#`, `##`, `###`
- RST `.. _label:` anchors → Remove (use heading anchors)
- RST `|image|` substitutions → Markdown `![alt](url)` inline
- RST `:ref:` cross-references → Markdown `[text](#anchor)` links

**New sections to add (interleaved with converted content):**

After the title/badges:
```markdown
Official CLI for Aiven cloud services — built for humans and AI agents.
```

After "Getting Started" section:
```markdown
## Agent Quick Start

For AI agents and CI/CD pipelines:

```bash
export AIVEN_AUTH_TOKEN=<your-token>
export AIVEN_PROJECT=<your-project>
avn service list --fields service_name,state,plan
```

See [AGENTS.md](AGENTS.md) for the full agent guide and [skills/](skills/) for per-service skill files.
```

After all human walkthroughs, before "Extra Features":
```markdown
## Command Groups

| Group | Description |
|-------|-------------|
| `service` | Create, manage, and terminate cloud services |
| `project` | Project management and user access |
| `cloud` | List available cloud regions |
| `vpc` | Virtual private cloud and peering |
| `account` | Account management, teams, OAuth2 |
| `organization` | Organization management and groups |
| `billing-group` | Billing groups and invoices |
| `user` | Authentication, tokens, and user management |
| `application-user` | Application user management |
| `permissions` | Role-based access control |
| `mirrormaker` | Kafka MirrorMaker replication |
| `static-ip` | Static IP address management |
| `byoc` | Bring Your Own Cloud configuration |
| `sustainability` | Carbon footprint estimates |
| `ticket` | Support ticket management |
| `events` | Project event log |

## AI Agent Integration

This CLI is designed for use by both humans and AI agents:

- **[AGENTS.md](AGENTS.md)** — Complete guide for agents using `avn`
- **[CLAUDE.md](CLAUDE.md)** — Guide for agents contributing code to this project
- **[skills/](skills/)** — Per-service skill files with workflows and examples
```

Before Contributing section:
```markdown
## Contributing

Check the [CONTRIBUTING](https://github.com/aiven/aiven-client/blob/main/.github/CONTRIBUTING.md) guide for human contributors. AI agents: see [CLAUDE.md](CLAUDE.md).
```

**Verify:**
- All content from README.rst is preserved in README.md
- All links work (relative paths, external URLs)
- No RST syntax remains
- `README.rst` is deleted

**Commit:**

```
docs: convert README.rst to README.md with agent integration sections

Faithful RST-to-Markdown conversion preserving all human-facing content.
Added Agent Quick Start, Command Groups table, and AI Agent Integration
section. Deleted README.rst.
```

---

## Phase 6: Verification

### Task 6: Cross-reference validation

Verify all artifacts are consistent:

**Step 1:** Check all skill file paths referenced in AGENTS.md exist:
```bash
# Extract skill paths from AGENTS.md and verify they exist
grep -oP 'skills/avn-[^/]+/SKILL\.md' AGENTS.md | while read f; do test -f "$f" || echo "MISSING: $f"; done
```

**Step 2:** Check all source file paths referenced in CLAUDE.md exist:
```bash
grep -oP 'aiven/client/\S+\.py' CLAUDE.md | sort -u | while read f; do test -f "$f" || echo "MISSING: $f"; done
```

**Step 3:** Check no RST references remain:
```bash
grep -r '\.rst' README.md AGENTS.md CLAUDE.md || echo "No RST references found"
```

**Step 4:** Verify README.rst is deleted:
```bash
test ! -f README.rst && echo "README.rst deleted" || echo "WARNING: README.rst still exists"
```

**Step 5:** Verify YAML frontmatter in all skills:
```bash
for f in skills/avn-*/SKILL.md; do head -1 "$f" | grep -q '^---$' || echo "BAD FRONTMATTER: $f"; done
```

**Fix any issues found, then commit:**

```
chore: fix cross-reference issues in agent documentation
```

(Only if fixes are needed.)

---

## Summary

| Phase | Task | Files | Commit |
|-------|------|-------|--------|
| 1 | Shared skill | `skills/avn-shared/SKILL.md` | `docs: add shared skill...` |
| 2 | 17 per-service skills | `skills/avn-*/SKILL.md` | `docs: add per-service skills...` |
| 3 | AGENTS.md expansion | `AGENTS.md` | `docs: expand AGENTS.md...` |
| 4 | CLAUDE.md creation | `CLAUDE.md` | `docs: add CLAUDE.md...` |
| 5 | README conversion | `README.md` (delete `.rst`) | `docs: convert README.rst...` |
| 6 | Verification | — | `chore: fix cross-reference...` (if needed) |
