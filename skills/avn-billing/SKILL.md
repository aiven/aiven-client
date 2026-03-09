---
name: avn-billing
version: 1.0.0
description: "Billing groups, invoices, credits, and payment management."
metadata:
  requires:
    bins: ["avn"]
---

# Billing Management

Manage billing groups, invoices, credits, and project billing assignments.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn billing-group create` | Create a billing group |
| `avn billing-group delete` | Delete a billing group |
| `avn billing-group get` | Get billing group details |
| `avn billing-group list` | List billing groups |
| `avn billing-group update` | Update billing group settings |
| `avn billing-group assign-projects` | Assign projects to a billing group |
| `avn billing-group credits-list` | List credits in a billing group |
| `avn billing-group credits-claim` | Claim a credit code |
| `avn billing-group events` | List billing events |
| `avn billing-group invoice-list` | List invoices |
| `avn billing-group invoice-lines` | List invoice line items |

There are also legacy top-level `avn credits list` and `avn credits claim` commands.

## Common Workflows

### Create a billing group and assign projects

```bash
avn billing-group create "Production" --json
avn billing-group assign-projects <billing-group-id> --project myproject1 --project myproject2
```

### Claim credits

```bash
avn billing-group credits-claim <billing-group-id> --code <credit-code>
```

### View invoices

```bash
avn billing-group invoice-list <billing-group-id> --json
```

## Gotchas

- Projects must be assigned to a billing group for billing to work correctly.
- `credits-claim` requires a credit code provided by Aiven.
- `billing-group-id` is a positional argument for most commands.
- Invoice line items can be large — use `--fields` to filter output.
