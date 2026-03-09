---
name: avn-organization
version: 1.0.0
description: "Organization management, groups, cards, and organization-level VPCs."
metadata:
  requires:
    bins: ["avn"]
---

# Organization Management

Manage organizations, user groups, payment cards, and organization-level VPCs.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

### Organizations

| Command | Description |
|---------|-------------|
| `avn organization create` | Create an organization |
| `avn organization delete` | Delete an organization |
| `avn organization list` | List organizations |
| `avn organization update` | Update organization name |

### Users & Groups

| Command | Description |
|---------|-------------|
| `avn organization user list` | List organization members |
| `avn organization user invite` | Invite a user |
| `avn organization group list` | List user groups |
| `avn organization group show` | Show group details |
| `avn organization group create` | Create a user group |
| `avn organization group update` | Update a user group |
| `avn organization group delete` | Delete a user group |

### Payment Cards

| Command | Description |
|---------|-------------|
| `avn organization card list` | List payment cards |
| `avn organization card create` | Add a payment card |
| `avn organization card delete` | Remove a payment card |

### Organization VPCs

| Command | Description |
|---------|-------------|
| `avn organization vpc list` | List organization VPCs |
| `avn organization vpc get` | Get VPC details |
| `avn organization vpc create` | Create an organization VPC |
| `avn organization vpc delete` | Delete an organization VPC |
| `avn organization vpc peering-connection create` | Create a peering connection |
| `avn organization vpc peering-connection delete` | Delete a peering connection |
| `avn organization vpc peering-connection list` | List peering connections |
| `avn organization vpc clouds list` | List available clouds for org VPCs |
| `avn organization vpc peering-connection user-peer-network-cidrs add` | Add peer network CIDR |
| `avn organization vpc peering-connection user-peer-network-cidrs delete` | Remove peer network CIDR |

## Common Workflows

### Create an organization

```bash
avn organization create "My Org" --json
```

### Manage organization VPCs

```bash
avn organization vpc create --organization-id <org-id> --cloud aws-us-east-1 --network-cidr 10.0.0.0/24 --json
avn organization vpc list --organization-id <org-id> --json
```

### Delete safely

```bash
avn organization delete --dry-run <org-id>
avn organization delete --force <org-id>
```

## Gotchas

- `--organization-id` is required for most operations.
- Organization VPCs (`organization vpc`) are different from project VPCs (`vpc`). Organization VPCs can be shared across projects.
- `organization delete` supports `--dry-run` and requires `--force` in non-interactive mode.
- `organization delete` is irreversible.
