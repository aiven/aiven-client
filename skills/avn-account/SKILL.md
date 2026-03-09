---
name: avn-account
version: 1.0.0
description: "Account management, teams, and OAuth2 client configuration."
metadata:
  requires:
    bins: ["avn"]
---

# Account Management

Manage accounts, teams, team membership, and OAuth2 clients.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

### Accounts

| Command | Description |
|---------|-------------|
| `avn account create` | Create an account |
| `avn account delete` | Delete an account |
| `avn account list` | List accounts |
| `avn account update` | Update account name |

### Teams

| Command | Description |
|---------|-------------|
| `avn account team list` | List teams in an account |
| `avn account team create` | Create a team |
| `avn account team delete` | Delete a team |
| `avn account team user-list` | List team members |
| `avn account team user-invite` | Invite a user to a team |
| `avn account team user-list-pending` | List pending invitations |
| `avn account team user-delete` | Remove a user from a team |
| `avn account team project-list` | List projects attached to a team |
| `avn account team project-attach` | Attach a team to a project |
| `avn account team project-detach` | Detach a team from a project |

### OAuth2 Clients

| Command | Description |
|---------|-------------|
| `avn account oauth2-client create` | Create an OAuth2 client |
| `avn account oauth2-client delete` | Delete an OAuth2 client |
| `avn account oauth2-client get` | Get OAuth2 client details |
| `avn account oauth2-client list` | List OAuth2 clients |
| `avn account oauth2-client update` | Update an OAuth2 client |
| `avn account oauth2-client redirect-list` | List redirect URIs |
| `avn account oauth2-client redirect-create` | Add a redirect URI |
| `avn account oauth2-client redirect-delete` | Remove a redirect URI |
| `avn account oauth2-client secret-list` | List client secrets |
| `avn account oauth2-client secret-create` | Create a client secret |
| `avn account oauth2-client secret-delete` | Delete a client secret |

## Common Workflows

### Create a team and attach to a project

```bash
avn account team create --team-name devs <account_id>
avn account team project-attach --team-id <team_id> --project myproject <account_id> --team-type developer
```

### Invite a member

```bash
avn account team user-invite --team-id <team_id> <account_id> user@example.com
```

## Gotchas

- Team types are `admin`, `developer`, `operator`, `read_only`.
- OAuth2 client secrets are shown only at creation time — save them immediately.
- `account_id` is a positional argument for all account commands.
- `--oauth2-client-id` is required for all OAuth2 sub-operations.
