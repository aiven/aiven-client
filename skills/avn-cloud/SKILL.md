---
name: avn-cloud
version: 1.0.0
description: "List available cloud regions and providers."
metadata:
  requires:
    bins: ["avn"]
---

# Cloud Regions

List available cloud regions for deploying Aiven services.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn cloud list` | List all available cloud regions |

## Common Workflows

### List all regions

```bash
avn cloud list --json
```

### Find regions for a specific provider

```bash
avn cloud list --json | jq '[.[] | select(.cloud_name | startswith("google-"))]'
```

## Gotchas

- Cloud names follow the pattern `<provider>-<region>` (e.g. `google-europe-west1`, `aws-us-east-1`, `azure-westeurope`).
- The list includes all regions across all providers. Filter client-side by prefix.
- Use the `cloud_name` value when creating services (`--cloud`) or VPCs.
