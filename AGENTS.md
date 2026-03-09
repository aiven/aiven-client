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
