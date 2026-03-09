---
name: avn-kafka
version: 1.0.0
description: "Kafka topics, ACLs, connectors, and Schema Registry operations."
metadata:
  requires:
    bins: ["avn"]
---

# Kafka Operations

Kafka-specific operations — topics, ACLs, connectors, and Schema Registry. All commands are under `avn service`.

## Prerequisites

See [avn-shared](../avn-shared/SKILL.md) for authentication and global flags.

## Subcommands

### Topics

| Command | Description |
|---------|-------------|
| `avn service topic-create` | Create a Kafka topic |
| `avn service topic-delete` | Delete a Kafka topic |
| `avn service topic-get` | Get topic details and partitions |
| `avn service topic-list` | List all topics |
| `avn service topic-update` | Update topic configuration |

### ACLs (Aiven ACL)

| Command | Description |
|---------|-------------|
| `avn service acl-add` | Add an Aiven-level ACL entry |
| `avn service acl-delete` | Delete an Aiven-level ACL entry |
| `avn service acl-list` | List Aiven-level ACL entries |

### ACLs (Kafka-native ACL)

| Command | Description |
|---------|-------------|
| `avn service kafka-acl-add` | Add a Kafka-native ACL entry |
| `avn service kafka-acl-delete` | Delete a Kafka-native ACL entry |
| `avn service kafka-acl-list` | List Kafka-native ACL entries |

### Schema Registry

| Command | Description |
|---------|-------------|
| `avn service schema-get` | Get a schema by ID |
| `avn service schema-create` | Register a new schema |
| `avn service schema-check` | Check schema compatibility |
| `avn service schema-configuration` | Get global compatibility level |
| `avn service schema-configuration-update` | Set global compatibility level |
| `avn service schema-subject-*` | Subject management (list, delete, config) |
| `avn service schema-subject-version-*` | Version management (list, get, schema, delete) |
| `avn service schema-registry-acl-add` | Add Schema Registry ACL |
| `avn service schema-registry-acl-delete` | Delete Schema Registry ACL |
| `avn service schema-registry-acl-list` | List Schema Registry ACLs |

### Connectors

| Command | Description |
|---------|-------------|
| `avn service connector-available` | List available connector plugins |
| `avn service connector-list` | List deployed connectors |
| `avn service connector-status` | Get connector status |
| `avn service connector-schema` | Get connector configuration schema |
| `avn service connector-create` | Deploy a new connector |
| `avn service connector-update` | Update connector configuration |
| `avn service connector-delete` | Delete a connector |
| `avn service connector-pause` | Pause a connector |
| `avn service connector-resume` | Resume a paused connector |
| `avn service connector-stop` | Stop a connector |
| `avn service connector-restart` | Restart a connector |
| `avn service connector-restart-task` | Restart a specific connector task |

## Common Workflows

### Create a topic with retention

```bash
avn service topic-create myservice --topic my-events --partitions 6 --replication 3 --retention 604800000 --project myproject
```

### Manage Aiven ACLs

```bash
avn service acl-add myservice --permission readwrite --topic 'my-events' --username 'my-app' --project myproject
avn service acl-list myservice --project myproject --json
```

### Deploy a connector

```bash
avn service connector-create myservice --project myproject -c '{"name":"my-sink","connector.class":"io.aiven.kafka.connect.s3.AivenKafkaConnectS3SinkConnector","topics":"my-events","aws.s3.bucket":"my-bucket"}'
```

### Register a schema

```bash
avn service schema-create myservice --project myproject --subject my-events-value --schema '{"type":"record","name":"Event","fields":[{"name":"id","type":"string"}]}'
```

## Gotchas

- **Two ACL systems:** Aiven ACL (`acl-*`) and Kafka-native ACL (`kafka-acl-*`). They are separate and cannot be mixed. Check which one your service uses.
- `--partitions` and `--replication` are required for `topic-create`.
- Schema Registry uses `--subject` (not `--topic`). Subject naming convention: `<topic>-key` or `<topic>-value`.
- Connector config is JSON passed via `-c` or `--connector-config`.
- `topic-delete` does not support `--dry-run` — it deletes immediately.
- `topic-get` shows partition details and consumer group offsets.
- `--retention` is in milliseconds.
