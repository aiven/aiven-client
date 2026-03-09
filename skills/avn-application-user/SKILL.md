---
name: avn-application-user
version: 1.0.0
description: "Organization-scoped application user and token management."
metadata:
  requires:
    bins: ["avn"]
---

# Application User Management

Create and manage application users and their tokens for programmatic access.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn application-user create` | Create an application user |
| `avn application-user delete` | Delete an application user |
| `avn application-user info` | Get application user details |
| `avn application-user list` | List application users |
| `avn application-user update` | Update application user name |
| `avn application-user token create` | Create a token for an application user |
| `avn application-user token list` | List tokens |
| `avn application-user token info` | Get token details |
| `avn application-user token revoke` | Revoke a token |

## Common Workflows

### Create an application user and token

```bash
avn application-user create --organization-id <org-id> --name "CI Pipeline" --json
avn application-user token create <user-id> --organization-id <org-id> --description "deploy token" --json
```

### List application users

```bash
avn application-user list --organization-id <org-id> --json
```

## Gotchas

- Application users are organization-scoped — `--organization-id` is required for all operations.
- Tokens are shown only at creation time — save them immediately.
- Application users are separate from regular user accounts.
- Use `avn permissions set` to grant application users access to specific projects.
