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
