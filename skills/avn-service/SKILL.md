---
name: avn-service
version: 1.0.0
description: "Create, manage, and terminate Aiven cloud services."
metadata:
  requires:
    bins: ["avn"]
---

# Service Management

Create, manage, and terminate Aiven cloud services.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

| Command | Description |
|---------|-------------|
| `avn service create` | Create a new service |
| `avn service get` | Get service details |
| `avn service list` | List services in a project |
| `avn service update` | Update service configuration, plan, or cloud |
| `avn service terminate` | Delete a service permanently |
| `avn service wait` | Wait until service reaches RUNNING state |
| `avn service plans` | List available service plans |
| `avn service types` | List available service types |
| `avn service versions` | List available versions for a service type |
| `avn service logs` | View service log entries |
| `avn service metrics` | View service metrics |
| `avn service cli` | Open interactive client (psql, mysql, valkey-cli) |
| `avn service backup-list` | List available backups |
| `avn service maintenance-start` | Start pending maintenance |
| `avn service migration-status` | Check migration progress |
| `avn service credentials-reset` | Reset service credentials |
| `avn service ca-get` | Download project CA certificate |
| `avn service keypair-get` | Download service keypair |
| `avn service database-create` | Create a database |
| `avn service database-delete` | Delete a database |
| `avn service database-list` | List databases |
| `avn service user-create` | Create a service user |
| `avn service user-delete` | Delete a service user |
| `avn service user-list` | List service users |
| `avn service user-get` | Get service user details |
| `avn service user-creds-download` | Download user credentials (cert, key, CA) |
| `avn service user-kafka-java-creds` | Generate Java keystore/truststore for Kafka |
| `avn service user-password-reset` | Reset a service user's password |
| `avn service connection-pool-create` | Create a PgBouncer connection pool |
| `avn service connection-pool-update` | Update a connection pool |
| `avn service connection-pool-delete` | Delete a connection pool |
| `avn service connection-pool-list` | List connection pools |
| `avn service connection-info-*` | Get connection strings (psql, kcat, pg uri) |
| `avn service tags-list` | List service tags |
| `avn service tags-update` | Add or update service tags |
| `avn service tags-replace` | Replace all service tags |
| `avn service integration-*` | Service integrations (create, list, delete, update) |
| `avn service integration-endpoint-*` | Integration endpoints |
| `avn service custom-file-*` | Custom file management (list, get, upload, update) |
| `avn service index-list` | List OpenSearch indices |
| `avn service index-delete` | Delete an OpenSearch index |
| `avn service queries` | View query statistics |
| `avn service current-queries` | View currently running queries |
| `avn service queries-reset` | Reset query statistics |
| `avn service task-create` | Create a service task (e.g. migration) |
| `avn service task-get` | Get task status |
| `avn service privatelink-*` | Private link management (AWS, Azure, Google) |
| `avn service flink-*` | Flink application management |
| `avn service m3-namespace-*` | M3 namespace management |
| `avn service opensearch-*` | OpenSearch security and snapshot management |
| `avn service clickhouse-database-*` | ClickHouse database management |
| `avn service alloydbomni-*` | AlloyDB Omni key management |
| `avn service sstableloader-*` | Cassandra SSTableLoader credentials and commands |

## Common Workflows

### Create a service and wait for it

```bash
avn service create mydb --project myproject --service-type pg --plan hobbyist --cloud google-europe-west1
avn service wait mydb --project myproject
avn service get mydb --project myproject --fields service_name,state,service_uri
```

### List services with field filtering

```bash
avn service list --project myproject --fields service_name,state,plan,cloud_name
```

### Get connection URI

```bash
avn service get mydb --project myproject --fields service_uri --format "{service_uri}"
```

### Power cycle a service

```bash
avn service update mydb --project myproject --power-off
avn service update mydb --project myproject --power-on
```

### Terminate safely

```bash
avn service terminate --dry-run mydb --project myproject
avn service terminate --force mydb --project myproject
```

## Gotchas

- `terminate` requires `--force` in non-interactive (piped) mode.
- Service names are unique per project.
- `service list` without a name lists all services; with a name it filters to that service.
- `wait` polls until the service reaches RUNNING state — it blocks.
- `--disk-space-gib` is only valid for plans that support additional disk.
- `service types -v` shows configurable options with examples.
- `-c KEY=VALUE` sets service-specific configuration (e.g. `-c pg_version=17`).
- Connection pool commands only work with PostgreSQL services.
- `user-creds-download` saves cert, key, and CA to the current directory.
