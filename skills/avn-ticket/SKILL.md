---
name: avn-ticket
version: 1.0.0
description: "Support ticket creation and management."
metadata:
  requires:
    bins: ["avn"]
---

# Support Tickets

Create and list Aiven support tickets.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn ticket create` | Create a support ticket |
| `avn ticket list` | List support tickets |

## Common Workflows

### Create a support ticket

```bash
avn ticket create --project myproject --severity low --title "Question about service" --description "Details here" --json
```

### List open tickets

```bash
avn ticket list --project myproject --json
```

## Gotchas

- Tickets are project-scoped — `--project` is required.
- Specifying `--severity` and `--service-name` helps with faster routing.
- Severity levels: `low`, `high`, `critical`.
