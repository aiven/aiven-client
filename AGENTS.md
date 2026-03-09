# Agent Guide for aiven-client (`avn`)

Official CLI for Aiven cloud services — built for humans and AI agents.

## Quick Start

```bash
export AIVEN_AUTH_TOKEN=<token>
export AIVEN_PROJECT=<project>
avn service list --fields service_name,state,plan
avn service get <name> --fields service_name,state,service_uri
```

## Authentication

Set these environment variables for headless (non-interactive) use:

```
AIVEN_AUTH_TOKEN=<your-token>    # Required: API authentication token
AIVEN_PROJECT=<default-project>  # Optional: default project for all commands
```

Tokens can be created via: `avn user access-token create --description "agent" --json`

**Credential files** (alternative to env vars):
- `~/.config/aiven/aiven-credentials.json` — `{"auth_token": "...", "user_email": "..."}`
- `~/.config/aiven/aiven-client.json` — `{"default_project": "..."}`

**Token rotation:** Create a new token before revoking the old one. Tokens are shown only at creation time.

## Output Behavior

- **Non-TTY (piped) contexts** automatically emit JSON. No `--json` flag needed.
- Force table output in pipes with `--no-auto-json`.
- Errors in non-TTY contexts are emitted as JSON to stdout: `{"error": true, "message": "...", "exit_code": 1}`
- Filter output fields with `--fields name,state,plan` to reduce token usage.
- **Discover available fields:** `avn <command> --json | head -1` to see all field names.

## Skills Directory

Each skill file documents subcommands, workflows, and gotchas for a command group.

| Skill | Path | Description |
|-------|------|-------------|
| avn-shared | [skills/avn-shared/SKILL.md](skills/avn-shared/SKILL.md) | Authentication, global flags, output, safety |
| avn-service | [skills/avn-service/SKILL.md](skills/avn-service/SKILL.md) | Service CRUD, lifecycle, types, integrations |
| avn-kafka | [skills/avn-kafka/SKILL.md](skills/avn-kafka/SKILL.md) | Kafka topics, ACLs, connectors, Schema Registry |
| avn-project | [skills/avn-project/SKILL.md](skills/avn-project/SKILL.md) | Project management and user access |
| avn-user | [skills/avn-user/SKILL.md](skills/avn-user/SKILL.md) | Login, tokens, user account management |
| avn-vpc | [skills/avn-vpc/SKILL.md](skills/avn-vpc/SKILL.md) | VPC and peering connections |
| avn-cloud | [skills/avn-cloud/SKILL.md](skills/avn-cloud/SKILL.md) | Cloud regions |
| avn-account | [skills/avn-account/SKILL.md](skills/avn-account/SKILL.md) | Accounts, teams, OAuth2 clients |
| avn-organization | [skills/avn-organization/SKILL.md](skills/avn-organization/SKILL.md) | Organizations, groups, org-level VPCs |
| avn-billing | [skills/avn-billing/SKILL.md](skills/avn-billing/SKILL.md) | Billing groups, invoices, credits |
| avn-mirrormaker | [skills/avn-mirrormaker/SKILL.md](skills/avn-mirrormaker/SKILL.md) | Kafka MirrorMaker replication flows |
| avn-static-ip | [skills/avn-static-ip/SKILL.md](skills/avn-static-ip/SKILL.md) | Static IP address management |
| avn-byoc | [skills/avn-byoc/SKILL.md](skills/avn-byoc/SKILL.md) | Bring Your Own Cloud configuration |
| avn-permissions | [skills/avn-permissions/SKILL.md](skills/avn-permissions/SKILL.md) | Role-based access control |
| avn-application-user | [skills/avn-application-user/SKILL.md](skills/avn-application-user/SKILL.md) | Application users and tokens |
| avn-sustainability | [skills/avn-sustainability/SKILL.md](skills/avn-sustainability/SKILL.md) | Carbon footprint estimates |
| avn-ticket | [skills/avn-ticket/SKILL.md](skills/avn-ticket/SKILL.md) | Support tickets |
| avn-events | [skills/avn-events/SKILL.md](skills/avn-events/SKILL.md) | Project event log |

## Destructive Commands

### Irreversible

- `avn service terminate <name>` — Deletes the service and all its data.
- `avn project delete <name>` — Deletes the project (services must be terminated first).
- `avn organization delete <id>` — Deletes the organization.

### Reversible but disruptive

- `avn service update <name> --power-off` — Powers off the service (can power on again).
- `avn service user-delete <service> --username <user>` — Deletes a service user.
- `avn service database-delete <service> --dbname <db>` — Deletes a database.

### Data-modifying

- `avn service topic-delete <service> --topic <topic>` — Deletes a Kafka topic.
- `avn service index-delete <service> --index <index>` — Deletes an OpenSearch index.

**Always use `--dry-run` first, then `--force` to skip interactive confirmation.**

## Common Workflows

### List services (agent-optimized)
```bash
avn service list --project myproject --fields service_name,state,plan,cloud_name
```

### Get service details
```bash
avn service get myservice --project myproject --fields service_name,state,service_uri
```

### Create a service and wait
```bash
avn service create myservice --project myproject --service-type pg --plan hobbyist --cloud google-europe-west1
avn service wait myservice --project myproject
avn service get myservice --project myproject --fields service_name,state,service_uri
```

### Terminate safely
```bash
avn service terminate --dry-run myservice --project myproject
avn service terminate --force myservice --project myproject
```

### Get connection URI
```bash
avn service get myservice --project myproject --fields service_uri --format "{service_uri}"
```

### Download credentials
```bash
avn service user-creds-download --username avnadmin myservice --project myproject
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Command failed (check JSON error on stdout) |
| 2    | Invalid usage / interrupted (SIGINT) |
| 13   | Output truncated (SIGPIPE) |

## Input Invariants

- Resource names (service, topic, index) must not contain: `..`, `?`, `#`, `%XX`, or control characters.
- All API calls go to `AIVEN_WEB_URL` (default: `https://api.aiven.io`).
- The CLI URL-encodes all path segments via `urllib.parse.quote(safe="")`.

## Rate Limits & Retries

The Aiven API has rate limits. On HTTP 429, wait and retry with exponential backoff. The CLI does not retry automatically.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AIVEN_AUTH_TOKEN` | API authentication token | — |
| `AIVEN_PROJECT` | Default project for all commands | — |
| `AIVEN_WEB_URL` | API base URL | `https://api.aiven.io` |
| `AIVEN_FORCE` | Set to `true` to skip confirmations | — |
| `AIVEN_CREDENTIALS_FILE` | Path to credentials JSON file | `~/.config/aiven/aiven-credentials.json` |
