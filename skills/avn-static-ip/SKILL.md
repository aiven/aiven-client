---
name: avn-static-ip
version: 1.0.0
description: "Static IP address management for Aiven services."
metadata:
  requires:
    bins: ["avn"]
---

# Static IP Management

Create, manage, and associate static IP addresses with Aiven services.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn static-ip create` | Create a static IP address |
| `avn static-ip delete` | Delete a static IP address |
| `avn static-ip list` | List static IP addresses |
| `avn static-ip associate` | Associate a static IP with a service |
| `avn static-ip dissociate` | Dissociate a static IP from a service |

## Common Workflows

### Create and associate a static IP

```bash
avn static-ip create --project myproject --cloud aws-us-east-1 --json
avn static-ip associate --project myproject --service myservice <static-ip-id>
```

### List static IPs

```bash
avn static-ip list --project myproject --json
```

## Gotchas

- Static IPs are cloud-specific — the cloud must match the service's cloud.
- Must dissociate a static IP before deleting it.
- Not all service types support static IPs.
- Static IP creation may take a moment — the IP is allocated from the cloud provider.
