---
name: avn-user
version: 1.0.0
description: "User authentication, access tokens, and account management."
metadata:
  requires:
    bins: ["avn"]
---

# User Management

Login, logout, access tokens, and user account operations.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn user login` | Authenticate interactively |
| `avn user logout` | Revoke the current session token |
| `avn user info` | Show current user information |
| `avn user create` | Create a new user account |
| `avn user password-change` | Change account password |
| `avn user tokens-expire` | Revoke ALL tokens (logs out all sessions) |
| `avn user access-token create` | Create an access token |
| `avn user access-token list` | List access tokens |
| `avn user access-token update` | Update token description |
| `avn user access-token revoke` | Revoke a specific token |

## Common Workflows

### Create an access token for automation

```bash
avn user access-token create --description "CI pipeline" --json
```

Save the token immediately — it is only shown once.

### Rotate tokens

```bash
avn user access-token list --json
avn user access-token revoke <old-token-prefix>
avn user access-token create --description "rotated $(date +%Y-%m-%d)" --json
```

### Token-based login (for agents)

```bash
export AIVEN_AUTH_TOKEN=<your-token>
avn user info --json
```

## Gotchas

- `logout` only revokes the current session token — other sessions remain valid.
- `tokens-expire` revokes ALL tokens and logs out all sessions everywhere.
- `access-token create` returns the full token only once — save it immediately.
- `access-token revoke` accepts a full token or a token prefix.
- `--max-age-seconds` and `--extend-when-used` are optional flags for `access-token create`.
- There is a system-enforced limit on the number of tokens per user. Revoke unused tokens.
