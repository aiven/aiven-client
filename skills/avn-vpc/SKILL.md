---
name: avn-vpc
version: 1.0.0
description: "Virtual private cloud management and peering connections."
metadata:
  requires:
    bins: ["avn"]
---

# VPC Management

Create and manage project VPCs and peering connections.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn vpc create` | Create a project VPC |
| `avn vpc delete` | Delete a project VPC |
| `avn vpc list` | List project VPCs |
| `avn vpc peering-connection create` | Create a peering connection |
| `avn vpc peering-connection delete` | Delete a peering connection |
| `avn vpc peering-connection get` | Get peering connection details |
| `avn vpc peering-connection list` | List peering connections |
| `avn vpc user-peer-network-cidr add` | Add a user-defined peer network CIDR |
| `avn vpc user-peer-network-cidr delete` | Remove a user-defined peer network CIDR |

## Common Workflows

### Create a VPC

```bash
avn vpc create --project myproject --cloud aws-us-east-1 --network-cidr 10.0.0.0/24 --json
```

### Set up a peering connection

```bash
avn vpc peering-connection create --project myproject --project-vpc-id <vpc-id> --peer-cloud-account <aws-account-id> --peer-vpc <peer-vpc-id> --peer-region us-east-1 --json
```

### List VPCs with state

```bash
avn vpc list --project myproject --json
```

## Gotchas

- `--cloud` and `--network-cidr` are required for `vpc create`.
- VPC deletion fails if services are still attached — terminate or move services first.
- Peering connections require the peer account ID, VPC ID, and region.
- VPC creation is asynchronous — poll the state until it reaches `ACTIVE`.
- Project VPCs (`avn vpc`) are different from organization VPCs (`avn organization vpc`).
