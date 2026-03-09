---
name: avn-mirrormaker
version: 1.0.0
description: "Kafka MirrorMaker 2 replication flow management."
metadata:
  requires:
    bins: ["avn"]
---

# MirrorMaker Replication

Manage Kafka MirrorMaker 2 replication flows for cross-cluster data replication.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn mirrormaker replication-flow create` | Create a replication flow |
| `avn mirrormaker replication-flow delete` | Delete a replication flow |
| `avn mirrormaker replication-flow get` | Get replication flow details |
| `avn mirrormaker replication-flow list` | List replication flows |
| `avn mirrormaker replication-flow update` | Update a replication flow |

## Common Workflows

### Create a replication flow

```bash
avn mirrormaker replication-flow create <mm2-service> --project myproject --source-cluster <source-kafka> --target-cluster <target-kafka> --json
```

### List replication flows

```bash
avn mirrormaker replication-flow list <mm2-service> --project myproject --json
```

## Gotchas

- Requires a running MirrorMaker 2 service.
- Source and target are Kafka service names (in the same project).
- The MirrorMaker 2 service must have integrations to both source and target Kafka services.
- Replication flow configuration uses `--topics` for topic patterns.
