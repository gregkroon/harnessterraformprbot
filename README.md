````markdown
# 🛠️ Harness Terraform Module Upgrade Bot

A GitHub App-powered Go bot that scans one or more repositories for outdated Terraform module versions and automatically creates pull requests to upgrade them. Ideal for platform and DevOps teams using GitHub and Harness to maintain Terraform infrastructure at scale.

---

## 🚀 What It Does

- 🔍 Scans GitHub repositories for Terraform modules
- 📦 Checks if newer versions exist (GitHub, Harness IACM Registry, Harness Account Registry)
- 🧠 Uses semantic versioning to:
  - Batch minor/patch upgrades into a single pull request
  - Create separate PRs for major upgrades
- ✅ Triggers Harness pipelines via PR webhook
- 🤖 Monitors PR checks and auto-merges successful ones
- 🧹 Cleans up branches post-merge
- 🔐 Uses GitHub App authentication (no PATs)

---

## 📦 Features

- Supports GitHub + Harness module registries
- Secure GitHub App authentication
- Multi-repo scanning
- PR monitoring and auto-merge
- CI/CD integration with Harness pipelines
- Docker-compatible for scheduled execution

---

## 🔐 GitHub App Authentication

This bot uses a **GitHub App** instead of a PAT for secure and scalable repo access.

### Required GitHub App Permissions

| Scope                  | Access Type | Purpose                          |
|------------------------|-------------|----------------------------------|
| Repository contents    | Read/Write  | Clone, commit, and push changes |
| Pull requests          | Read/Write  | Create, update, monitor PRs     |
| Checks                 | Read        | Monitor CI/CD pipeline status   |
| Installations          | Read        | Fetch access tokens             |

---

## 🧰 Getting Started

### 1. Clone and Build

```bash
git clone https://github.com/gregkroon/harnessterraformprbot.git
cd harnessterraformprbot
go build -o terraform-upgrade-bot .
````
