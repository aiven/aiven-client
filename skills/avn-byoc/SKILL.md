---
name: avn-byoc
version: 1.0.0
description: "Bring Your Own Cloud (BYOC) configuration and provisioning."
metadata:
  requires:
    bins: ["avn"]
---

# Bring Your Own Cloud (BYOC)

Configure and provision BYOC environments to run Aiven services in your own cloud account.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn byoc create` | Create a BYOC configuration |
| `avn byoc delete` | Delete a BYOC configuration |
| `avn byoc list` | List BYOC configurations |
| `avn byoc provision` | Provision a BYOC environment |
| `avn byoc update` | Update a BYOC configuration |
| `avn byoc cloud permissions get` | Get cloud permissions |
| `avn byoc cloud permissions set` | Set cloud permissions |
| `avn byoc cloud permissions add` | Add cloud permissions |
| `avn byoc cloud permissions remove` | Remove cloud permissions |
| `avn byoc tags-list` | List BYOC tags |
| `avn byoc tags-update` | Add or update tags |
| `avn byoc tags-replace` | Replace all tags |
| `avn byoc template terraform get-template` | Download Terraform template |
| `avn byoc template terraform get-vars` | Download Terraform variables |

## Common Workflows

### Set up BYOC

```bash
avn byoc create --organization-id <org-id> --cloud aws-us-east-1 --json
avn byoc template terraform get-template --organization-id <org-id> --byoc-id <id>
avn byoc provision --organization-id <org-id> --byoc-id <id>
```

### List BYOC configurations

```bash
avn byoc list --organization-id <org-id> --json
```

## Gotchas

- BYOC requires organization-level access.
- Provisioning is asynchronous — check status after creation.
- `--organization-id` is required for all BYOC commands.
- The Terraform template must be applied in your cloud account before provisioning.
