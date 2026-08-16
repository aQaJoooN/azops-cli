# azops-cli

A CLI tool for reconciling Azure DevOps Server project settings, permissions, pipelines, and service integrations from a declarative YAML configuration.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Configuration Files](#configuration-files)
  - [config.yaml](#configyaml)
  - [secret.yaml](#secretyaml)
- [Component Selectors](#component-selectors)
- [Execution Model](#execution-model)
- [Supported Modules](#supported-modules)
- [Group Aliases](#group-aliases)
- [Dry Run](#dry-run)
- [Output](#output)
- [Project Structure](#project-structure)

---

## Overview

`azops-cli` applies a desired state defined in YAML to an Azure DevOps Server project. It reads a config file and an optional secret file, plans the changes needed to reach that state, and applies them in dependency order across six execution stages.

Modules that are absent from the config file are silently skipped. All output is redacted of PAT tokens and secret values before being written to stdout.

---

## Requirements

- Go 1.24+
- Azure DevOps Server 2022.2
- A Personal Access Token (PAT) with sufficient scopes for the components you are reconciling

---

## Installation

Build from source:

```bash
go build -o azops ./cmd/azops
```

On Windows:

```cmd
go build -o azops.exe ./cmd/azops
```

---

## Usage

```
azops apply <selector> [options]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | `-u` | `$AZOPS_AZURE_URL` | Azure DevOps Server base URL |
| `--config` | `-c` | `./config.yaml` | Path to the config file |
| `--secret` | `-s` | `./secret.yaml` | Path to the secret file |
| `--dry-run` | | `false` | Preview planned changes without applying them |

### Examples

Apply everything:

```bash
azops apply all --url https://devops.example.com
```

Apply only project settings components:

```bash
azops apply projectsettings --url https://devops.example.com
```

Apply one specific component:

```bash
azops apply projectsettings.security --url https://devops.example.com
```

Dry run with explicit file paths:

```bash
azops apply all --config ./config.yaml --secret ./secret.yaml --dry-run
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AZOPS_AZURE_URL` | Azure DevOps Server base URL (overridden by `--url`) |
| `AZOPS_AZURE_PAT` | Personal Access Token (required, no CLI flag) |
| `AZOPS_CONFIG_FILE` | Config file path (overridden by `--config`) |
| `AZOPS_SECRET_FILE` | Secret file path (overridden by `--secret`) |

The PAT is only accepted via environment variable and is never accepted on the command line to prevent it appearing in shell history or process listings.

---

## Configuration Files

### config.yaml

Describes the full desired state of the project. Only sections present in the file are reconciled — omitting a section means that component is left untouched.

Top-level structure:

```yaml
general:
  teamprojectname: <string>           # Azure DevOps project name
  groupnametemplate: "<teamprojectname> <team> <role>"  # name template
  groupsalias:                        # short aliases for each group
    <team>:
      <role>: "<alias>"

projectsettings:
  overview: ...
  security: ...
  servicehook: ...
  dashboards: ...
  repositories: ...
  agentpools: ...
  settings: ...
  release: ...
  serviceconnections: ...
  test: ...

pipelines:
  pipelines: ...
  environments: ...
  library: ...
  releases: ...
  taskgroups: ...
  deploymentgroup: ...
```

#### general

```yaml
general:
  teamprojectname: testTeamProject
  groupnametemplate: "teamprojectname team role"
  groupsalias:
    Dev:
      SuperAdmins: "11"
      Admins: "12"
      Members: "13"
      Readers: "14"
      PR Approvers: "15"
    DevOps:
      Admins: "22"
      Members: "23"
```

- `teamprojectname` — the exact Azure DevOps project name.
- `groupnametemplate` — a string containing the three placeholders `teamprojectname`, `team`, and `role`. The CLI expands them to form the actual group name. For example `"testTeamProject Dev Admins"`.
- `groupsalias` — maps each team/role pair to a short alias string used throughout the rest of the config. Aliases must be unique across all teams.

#### projectsettings.overview

Controls which Azure DevOps services are enabled for the project.

```yaml
overview:
  boards: "disable"
  repos: "enable"
  pipelines: "enable"
  testplans: "disable"
  artifacts: "disable"
```

Accepted values: `"enable"` / `"disable"`.

#### projectsettings.security

Creates project groups and sets project-level permissions.

```yaml
security:
  creategroup: true
  permissions:
    View_analytics:
      Allow:
        - "all"
    Delete_this_node:
      Deny:
        - "all"
    Rename_team_project:
      Deny:
        - "11"
        - "12"
```

- `creategroup` — when `true`, missing groups are created automatically.
- `permissions` — a map of permission name → access value → list of group aliases.
- Access values: `Allow`, `Deny`, `Not_Set`.
- Use the alias `"all"` to target every group in the project whose name starts with the project name.

#### projectsettings.servicehook

Declares service hook subscriptions to create or update. Credentials come from the secret file.

```yaml
servicehook:
  create:
    - "new webhook 1"
    - "new webhook 2"
```

Each name must have a matching entry in `secret.yaml` under `projectsettings.servicehook`.

#### projectsettings.dashboards

Sets dashboard creation/edit/delete flags.

```yaml
dashboards:
  Security:
    Create_dashboards: false
    Edit_dashboards: false
    Delete_dashboards: false
```

#### projectsettings.repositories

Sets repository policies and access permissions across all repositories.

```yaml
repositories:
  policies:
    Maximum_file_size: "10 MB"   # e.g. 1 KB, 10 MB, 1 GB
  permissions:
    Contribute:
      Allow:
        - "11"
        - "12"
      Not_Set:
        - "14"
```

#### projectsettings.agentpools

Assigns roles to groups per agent pool.

```yaml
agentpools:
  permissions:
    - agentPoolName: "Default"
      permission:
        User:
          - "all"
    - agentPoolName: "win25"
      permission:
        Reader:
          - "14"
```

Supported roles: `Administrator`, `User`, `Reader`.

#### projectsettings.settings

Controls pipeline retention policies and build/trigger toggles.

```yaml
settings:
  Retention_policy:
    Days_to_keep_artifacts_symbols_and_attachments: 20
    Days_to_keep_runs: 731
    Days_to_keep_pull_request_runs: 20
    Number_of_recent_runs_to_retain_per_pipeline: 5
  General:
    Disable_anonymous_access_to_badges: "on"
    Limit_variables_that_can_be_set_at_queue_time: "on"
    Protect_access_to_repositories_in_YAML_pipelines: "on"
    Disable_creation_of_classic_build_pipelines: "off"
    Disable_creation_of_classic_release_pipelines: "off"
    Enable_shell_tasks_arguments_validation: "off"
  Triggers:
    Disable_implied_YAML_CI_trigger: "off"
```

All `General` and `Triggers` values accept `"on"` / `"off"`. All retention values must be greater than zero.

#### projectsettings.release

Sets release retention policies.

```yaml
release:
  Maximum_retention_policy:
    Days_to_retain_a_release: 20
    Minimum_releases_to_keep: 3
  Default_retention_policy:
    Days_to_retain_a_release: 20
    Minimum_releases_to_keep: 3
    Retain_build: true
  Permanently_destroy_releases:
    Days_to_keep_releases_after_deletion: 731
```

#### projectsettings.serviceconnections

Creates service connections and assigns roles. Credentials come from the secret file.

```yaml
serviceconnections:
  create:
    - "Docker Repository"
    - "Nuget Repository"
  permissions:
    Creator:
      - "11"
      - "22"
    User:
      - "13"
    Reader:
      - "14"
```

#### projectsettings.test

Sets test result retention policies.

```yaml
test:
  Retention:
    Days_to_keep_automated_test_runs_results_and_attachments_when_not_associated_with_pipeline: 20
    Days_to_keep_manual_test_runs_results_and_attachments: 20
```

#### pipelines.pipelines

Sets build pipeline permissions per folder path.

```yaml
pipelines:
  pipelines:
    permissions:
      - path: "root"        # maps to the / root folder
        permission:
          View_builds:
            Allow:
              - "11"
              - "12"
            Not_Set:
              - "14"
      - path: "Dev"         # maps to the /Dev folder
        permission:
          Edit_build_pipeline:
            Allow:
              - "13"
```

Use `"root"` or `"/"` for the root folder. Folder names are case-sensitive.

#### pipelines.environments

Assigns roles to groups for all environments.

```yaml
environments:
  permissions:
    Administrator:
      - "11"
    Creator:
      - "23"
    User:
      - "12"
    Reader:
      - "13"
      - "14"
```

#### pipelines.library

Creates variable groups and assigns roles. Variable values come from the secret file.

```yaml
library:
  create:
    - "nexusRepository"
    - "Database Build Server"
  permissions:
    Administrator:
      - "11"
    Creator:
      - "23"
    User:
      - "12"
    Reader:
      - "13"
```

#### pipelines.releases

Sets release pipeline permissions per folder path. Same path semantics as `pipelines.pipelines`.

#### pipelines.taskgroups

Sets task group access permissions.

```yaml
taskgroups:
  permissions:
    Administer_task_group_permissions:
      Allow:
        - "11"
    Edit_task_group:
      Allow:
        - "12"
        - "22"
```

#### pipelines.deploymentgroup

Assigns roles to groups for deployment groups.

```yaml
deploymentgroup:
  permissions:
    Administrator:
      - "11"
    User:
      - "12"
      - "22"
```

---

### secret.yaml

Contains sensitive values required by some modules. If the file is absent, the CLI continues with a warning and skips secret-dependent operations.

```yaml
projectsettings:
  servicehook:
    - name: "new webhook 1"
      event: "Pull request created"
      url: "https://hooks.example.com/webhook"
    - name: "new webhook 2"
      event: "Pull request updated"
      url: "https://hooks.example.com/webhook"

  serviceconnections:
    - name: "Docker Repository"
      type: "Docker Registry"
      url: "https://registry.example.com"
      user: "myuser"
      password: "mypassword"
      grant_access: true

    - name: "Nuget Repository"
      type: "NuGet"
      auth: "ApiKey"
      url: "https://nuget.example.com"
      apiKey: "my-api-key"

    - name: "NPM Repository"
      type: "npm"
      auth: "user and pass"
      url: "https://npm.example.com"
      user: "myuser"
      password: "mypassword"

    - name: "SonarQubeConnection"
      type: "Generic"
      auth: "token"
      url: "https://sonar.example.com"
      token: "my-token"

pipelines:
  library:
    - name: "nexusRepository"
      variables:
        - name: "nexus_url"
          value: "https://nexus.example.com"
        - name: "nexus_user"
          value: "myuser"
        - name: "nexus_pass"
          value: "mypassword"
```

#### Supported service connection types

| `type` | Required `auth` | Required fields |
|--------|----------------|-----------------|
| `Docker Registry` | _(none)_ | `user`, `password` |
| `NuGet` | `ApiKey` | `apiKey` |
| `npm` | `user and pass` | `user`, `password` |
| `npm` | `token` | `token` |
| `npm` | `ApiKey` | `apiKey` |
| `Generic` | `user and pass` | `user`, `password` |
| `Generic` | `token` | `token` |
| `Generic` | `ApiKey` | `apiKey` |

#### Supported service hook events

- `Pull request commented on`
- `Pull request created`
- `Pull request updated`
- Any event ID prefixed with `ms.vss-`

---

## Component Selectors

The selector argument controls which modules are reconciled.

| Selector | Modules run |
|----------|-------------|
| `all` | Every module present in the config |
| `projectsettings` | All `projectsettings.*` modules |
| `pipelines` | All `pipelines.*` modules |
| `projectsettings.security` | Security module only |
| `projectsettings.repositories` | Repositories module only |
| `projectsettings.dashboards` | Dashboards module only |
| `projectsettings.agentpools` | Agent pools module only |
| `projectsettings.release` | Release retention module only |
| `projectsettings.serviceconnections` | Service connections module only |
| `projectsettings.test` | Test retention module only |
| `projectsettings.servicehook` | Service hooks module only |
| `projectsettings.settings` | Pipeline settings module only |
| `projectsettings.overview` | Overview module only |
| `pipelines.environments` | Environments module only |
| `pipelines.library` | Library/variable groups module only |
| `pipelines.taskgroups` | Task groups module only |
| `pipelines.deploymentgroup` | Deployment groups module only |
| `pipelines.pipelines` | Build pipeline permissions only |
| `pipelines.releases` | Release pipeline permissions only |

---

## Execution Model

Modules run in six ordered stages. All modules within the same stage run concurrently. If any module in a stage fails, execution stops before the next stage begins.

| Stage | Modules |
|-------|---------|
| 1 | `projectsettings.security` |
| 2 | `projectsettings.repositories`, `projectsettings.dashboards`, `projectsettings.agentpools`, `projectsettings.release`, `projectsettings.serviceconnections`, `projectsettings.test` |
| 3 | `pipelines.environments`, `pipelines.library`, `pipelines.taskgroups`, `pipelines.deploymentgroup` |
| 4 | `pipelines.pipelines`, `pipelines.releases` |
| 5 | `projectsettings.servicehook` |
| 6 | `projectsettings.settings`, `projectsettings.overview` |

Security runs first because later modules depend on the groups it creates.

---

## Supported Modules

| Module | What it manages |
|--------|----------------|
| `projectsettings.security` | Project groups (create) and project-level ACL |
| `projectsettings.repositories` | Maximum file size policy and repository ACL |
| `projectsettings.dashboards` | Dashboard create/edit/delete security flags |
| `projectsettings.agentpools` | Per-pool role assignments |
| `projectsettings.release` | Release retention policies |
| `projectsettings.serviceconnections` | Service connection upsert and role assignments |
| `projectsettings.test` | Test result retention policies |
| `projectsettings.servicehook` | Service hook subscription upsert |
| `projectsettings.settings` | Pipeline settings, retention, and trigger flags |
| `projectsettings.overview` | Project service enable/disable flags |
| `pipelines.environments` | Environment role assignments |
| `pipelines.library` | Variable group upsert and library role assignments |
| `pipelines.taskgroups` | Task group ACL |
| `pipelines.deploymentgroup` | Deployment group role assignments |
| `pipelines.pipelines` | Build pipeline folder ACL |
| `pipelines.releases` | Release pipeline folder ACL |

---

## Group Aliases

Aliases are short identifiers you define in `general.groupsalias` and reuse everywhere in the config. They keep permission sections concise and make bulk changes easy.

```yaml
general:
  groupsalias:
    Dev:
      Admins: "12"
      Members: "13"
```

In a permission block you then write:

```yaml
Contribute:
  Allow:
    - "12"
    - "13"
```

The special alias `"all"` always refers to every group in the project whose name starts with the project name. It cannot be used as a user-defined alias.

---

## Dry Run

Pass `--dry-run` to see every planned change without making any API calls that modify state. The output shows the same stage/module breakdown but marks outcomes as `planned` instead of `changed`.

```bash
azops apply all --dry-run
```

---

## Output

Each run prints a stage-by-stage result followed by a summary line.

```
Stage 1
  projectsettings.security: changed
    change: create project group testTeamProject Dev Admins
    change: set project permissions: 3 assignment(s)
Stage 2
  projectsettings.repositories: unchanged
  projectsettings.agentpools: changed
    change: set agent pool roles: Default
Stage 5
  projectsettings.servicehook: changed
    change: create service hook new webhook 1
Final: success (changed=2 unchanged=1 planned=0 failed=0)
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | All modules succeeded |
| `1` | One or more modules failed, or a runtime error occurred |
| `2` | Invalid command-line usage |

---

## Project Structure

```
azops-cli/
├── cmd/azops/
│   ├── main.go          # entry point, run() orchestration
│   └── services.go      # wires Azure services into module dependencies
├── internal/
│   ├── azure/           # HTTP client and REST service adapters
│   ├── cli/             # argument parsing and connection resolution
│   ├── config/          # YAML types, loader, validator, enums
│   ├── detector/        # registry of module factories, execution graph builder
│   ├── domain/          # core interfaces, plan/result types, error types
│   ├── modules/
│   │   ├── permissions/ # group directory, PlanAccess, PlanRoles helpers
│   │   ├── pipelines/   # pipeline, environment, library, task group modules
│   │   └── projectsettings/ # security, repo, dashboard, hook, settings modules
│   ├── report/          # output renderer and secret redactor
│   └── runner/          # concurrent stage executor
├── sample.config.yaml
├── sample.secret.yaml
└── go.mod
```
