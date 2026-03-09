# Agent-Ready Documentation & Skills Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement the plan created from this design.

**Goal:** Make aiven-client fully discoverable and usable by AI agents through comprehensive documentation artifacts (AGENTS.md, CLAUDE.md, README.md) and a skills directory covering all 16 command groups.

**Audiences:**
- **Agent-as-user** — AI agents that use `avn` to manage Aiven infrastructure
- **Agent-as-developer** — AI agents that contribute code to aiven-client

**Reference:** [googleworkspace/cli](https://github.com/googleworkspace/cli) — a CLI built for humans and AI agents with 89 skills, AGENTS.md, and CLAUDE.md.

---

## Artifacts

| Artifact | Audience | Lines (est.) | Status |
|----------|----------|-------------|--------|
| `skills/avn-shared/SKILL.md` | Agent-as-user | ~180 | New |
| `skills/avn-*/SKILL.md` (x17) | Agent-as-user | ~40-150 each | New |
| `AGENTS.md` | Agent-as-user | ~220 | Expand (from 67 lines) |
| `CLAUDE.md` | Agent-as-developer | ~250 | New |
| `README.md` | Both | ~380 | New (replaces README.rst) |

---

## 1. Directory Structure

```
aiven-client/
├── AGENTS.md
├── CLAUDE.md
├── README.md                          # Replaces README.rst
├── skills/
│   ├── avn-shared/SKILL.md            # Auth, global flags, output, safety
│   ├── avn-service/SKILL.md           # Service CRUD, lifecycle, types
│   ├── avn-project/SKILL.md           # Project management
│   ├── avn-kafka/SKILL.md             # Kafka topics, ACLs, connectors, schemas
│   ├── avn-user/SKILL.md              # Login, tokens, access management
│   ├── avn-vpc/SKILL.md               # VPC peering, networks
│   ├── avn-cloud/SKILL.md             # Cloud regions
│   ├── avn-account/SKILL.md           # Account teams, OAuth2
│   ├── avn-organization/SKILL.md      # Org management
│   ├── avn-billing/SKILL.md           # Billing groups, credits
│   ├── avn-mirrormaker/SKILL.md       # MirrorMaker replication
│   ├── avn-static-ip/SKILL.md         # Static IP management
│   ├── avn-byoc/SKILL.md              # Bring Your Own Cloud
│   ├── avn-permissions/SKILL.md       # Permission management
│   ├── avn-application-user/SKILL.md  # Application users
│   ├── avn-sustainability/SKILL.md    # Carbon footprint
│   ├── avn-ticket/SKILL.md            # Support tickets
│   └── avn-events/SKILL.md            # Event log
```

Naming convention: `avn-<command-group>` mirrors `avn <command-group>`.

---

## 2. Shared Skill (`avn-shared/SKILL.md`)

Foundation all other skills reference. YAML frontmatter + Markdown body.

```yaml
---
name: avn-shared
version: 1.0.0
description: "avn CLI: Shared patterns for authentication, global flags, output formatting, and safety."
metadata:
  requires:
    bins: ["avn"]
---
```

**Sections:**
1. Installation — pip, uvx, verify
2. Authentication — env vars, token creation, credential file paths
3. Global Flags — `--json`, `--no-auto-json`, `--fields`, `--format`, `--dry-run`, `--force`, `--project`
4. Output Behavior — Non-TTY auto-JSON, structured errors, exit codes
5. CLI Syntax — `avn <group> <subcommand> [flags] [positional]`
6. Safety Rules — `--dry-run` before destructive ops, never output tokens
7. Input Invariants — Forbidden patterns in resource IDs

Self-contained: an agent can read only this file and use `avn` safely.

---

## 3. Per-Service Skill Format

Consistent template across all 17 command-group skills:

```yaml
---
name: avn-<group>
version: 1.0.0
description: "<one-liner>"
metadata:
  requires:
    bins: ["avn"]
---
```

**Standard sections:**
1. Title & one-liner
2. Prerequisites — "See avn-shared for authentication and global flags"
3. Subcommands table — command, description, key flags
4. Common workflows — 3-5 agent-optimized examples with `--fields`
5. Gotchas — pitfalls that `--help` won't tell you

Skills focus on what an agent needs beyond `--help`: workflows, gotchas, field names, safe patterns. No full flag docs per subcommand.

**Sizing:** Large groups (service, kafka) ~100-150 lines. Small groups (cloud, events) ~40-60 lines.

---

## 4. AGENTS.md (Expanded)

Definitive agent-as-user guide. Expanded from current 67 lines to ~220.

**Sections:**
1. Overview — what `avn` is, dual-audience positioning
2. Quick Start — 5-line copy-paste block
3. Authentication — env vars, token creation, credential paths, rotation
4. Output Behavior — auto-JSON, field discovery, structured errors
5. Skills Directory — table of all 18 skills with one-liners
6. Destructive Commands — full list categorized by risk level
7. Common Workflows — multi-step flows (create → wait → connect)
8. Exit Codes
9. Input Invariants
10. Rate Limits & Retries
11. Environment Variables — complete reference table

---

## 5. CLAUDE.md (Agent-as-Developer Guide)

Comprehensive guide for AI agents contributing code. ~250 lines.

**Sections:**
1. Project Overview — Python CLI, argparse, Aiven REST API
2. Build & Test — `make install-py`, `make test`, `make lint`, `make reformat`, `make all`
3. Source Layout — table mapping files to purpose
4. How to Add a New Command — step-by-step with naming conventions
5. How to Add a New Argument — shared args vs inline args
6. Coding Conventions — method naming, `self.client()`, `self.get_project()`, `self.print_response()`
7. Testing Patterns — `build_aiven_cli`, `mock_config`, mock client
8. Agent-Ready Requirements — checklist for new commands
9. Commit Conventions
10. PR Conventions

---

## 6. README.md (Replaces README.rst)

RST → Markdown conversion with restructuring for dual audience. ~380 lines.

**Sections:**
1. Title & badges
2. Tagline — "Official CLI for Aiven cloud services — built for humans and AI agents."
3. Getting Started — install, verify, login (converted from RST)
4. Agent Quick Start — 5 lines, points to AGENTS.md
5. Usage — help, --json, --format (converted from RST)
6. Command Groups — table of all 16 groups with one-liners
7. Human Walkthroughs — condensed from current RST examples
8. AI Agent Integration — skills overview, links to AGENTS.md and CLAUDE.md
9. Extra Features — autocomplete, auth helpers
10. Contributing — link to CONTRIBUTING.md + "AI agents: see CLAUDE.md"

README.rst is deleted, not kept alongside.

---

## 7. Implementation Order

Bottom-up: skills first, docs follow.

1. Shared skill (establishes patterns)
2. All 17 per-service skills (one commit)
3. AGENTS.md expansion
4. CLAUDE.md creation
5. README.md conversion (deletes README.rst)

**Commit strategy:** One commit per logical unit (5 commits total).

---

## 8. Out of Scope

- No code changes (covered by separate implementation plan)
- No CI/CD changes
- No skill registry or validation tooling
- No Gemini/OpenClaw integration metadata
