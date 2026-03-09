---
name: avn-sustainability
version: 1.0.0
description: "Carbon footprint estimates for Aiven services and projects."
metadata:
  requires:
    bins: ["avn"]
---

# Sustainability

Estimate carbon emissions for Aiven service plans and projects.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn sustainability project-emissions-estimate` | Estimate total project emissions |
| `avn sustainability service-plan-emissions-project` | Estimate emissions for a service plan |

## Common Workflows

### Estimate project carbon footprint

```bash
avn sustainability project-emissions-estimate --project myproject --json
```

### Compare plan emissions

```bash
avn sustainability service-plan-emissions-project --project myproject --service-type pg --cloud google-europe-west1 --plan hobbyist --json
```

## Gotchas

- Emissions are estimates, not exact measurements.
- Estimates depend on the cloud region and service plan.
