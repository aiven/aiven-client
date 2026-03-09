---
name: avn-events
version: 1.0.0
description: "View project management event log."
metadata:
  requires:
    bins: ["avn"]
---

# Events

View the management event log for a project.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Usage

```bash
avn events --project myproject
```

`avn events` is a direct command — it has no subcommands.

## Common Workflows

### View recent project events

```bash
avn events --project myproject --json
```

## Gotchas

- Events are project-scoped — uses `--project` flag.
- Shows management events (service creation, user changes, configuration updates), not service-level application logs.
- For service-level logs, use `avn service logs` instead.
