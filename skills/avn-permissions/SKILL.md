---
name: avn-permissions
version: 1.0.0
description: "Role-based permission management for organizations and projects."
metadata:
  requires:
    bins: ["avn"]
---

# Permission Management

Manage role-based permissions for organizations, organizational units, and projects.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn permissions list` | List permissions for a resource type |
| `avn permissions set` | Set permissions for a principal on a resource |

## Common Workflows

### List permissions

```bash
avn permissions list --organization-id <org-id> --resource-type project --json
```

### Set role for a user on a project

```bash
avn permissions set --organization-id <org-id> --resource-type project --resource-id <project-id> --principal-id <user-id> --principal-type user --permission developer
```

## Gotchas

- `set` **replaces** all existing permissions for the specified resource/principal pair — it is not additive.
- `--resource-type` must be one of: `organization`, `organization_unit`, `project`.
- `--principal-type` is typically `user` or `application_user`.
- `--organization-id` is required for all permission operations.
- Multiple `--permission` flags can be passed to assign multiple roles.
