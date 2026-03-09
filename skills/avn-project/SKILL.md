---
name: avn-project
version: 1.0.0
description: "Project management, user access, and configuration."
metadata:
  requires:
    bins: ["avn"]
---

# Project Management

Manage Aiven projects, user access, and project-level settings.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn project create` | Create a new project |
| `avn project delete` | Delete a project (irreversible) |
| `avn project details` | Show project details |
| `avn project list` | List all projects |
| `avn project switch` | Change the locally active project |
| `avn project update` | Update project settings |
| `avn project ca-get` | Download the project CA certificate |
| `avn project tags-list` | List project tags |
| `avn project tags-update` | Add or update project tags |
| `avn project tags-replace` | Replace all project tags |
| `avn project user-invite` | Invite a user to the project |
| `avn project user-list` | List project members |
| `avn project user-remove` | Remove a user from the project |
| `avn project invite-list` | List pending invitations |
| `avn project generate-sbom` | Generate a software bill of materials |

## Common Workflows

### Create a project

```bash
avn project create myproject --cloud aws-us-east-1
```

### Invite a user

```bash
avn project user-invite somebody@example.com --project myproject
avn project user-list --project myproject --json
```

### Switch active project

```bash
avn project switch myproject
avn project details
```

### Delete safely

```bash
avn project delete --dry-run myproject
avn project delete --force myproject
```

## Gotchas

- `delete` is irreversible — all services in the project must be terminated first.
- `delete` supports `--dry-run` and requires `--force` in non-interactive mode.
- `switch` changes the local default project (stored in `~/.config/aiven/aiven-client.json`), not a server-side setting.
- `--cloud` on `create` sets the default cloud for new services in the project.
- `ca-get` saves the CA certificate to the current directory.
