# 🛠️ Harness Terraform Module Upgrade Bot

A Harness powered Go bot that scans one or more repositories for outdated Terraform module versions and automatically creates pull requests to upgrade them. Ideal for platform and DevOps teams using GitHub and Harness to maintain Terraform infrastructure at scale.

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
```

### 2. Build and Push Docker Image

```bash
docker build -t munkys123/harnessterraformprbot:latest .
docker push munkys123/harnessterraformprbot:latest
```
## 🐳 Example Harness Scheduled Upgrade Pipeline (Cron Trigger)

You can run this bot on a schedule in Harness via a **cron-triggered pipeline**.

```yaml
pipeline:
  name: Scheduled Upgrade
  identifier: Scheduled_Upgrade
  projectIdentifier: westpacmvp
  orgIdentifier: default
  stages:
    - stage:
        name: PR Bot
        identifier: PR_Bot
        type: IACM
        spec:
          platform:
            os: Linux
            arch: Amd64
          runtime:
            type: Cloud
            spec: {}
          workspace: westpac
          execution:
            steps:
              - step:
                  type: Run
                  name: PR bot
                  identifier: PR_bot
                  spec:
                    connectorRef: account.dockerhubkroon
                    image: munkys123/harnessterraformprbot:latest
                    shell: Bash
                    command: /terraform-upgrade-bot
                    envVariables:
                      HARNESS_API_KEY: <+secrets.getValue("Harness_API_Key")>
                      GROUP_BRANCH_NAME: bot-terraform-upgrades
                      GITHUB_REPOS: terraform-module-upgrade-demo-harnessrepo1,terraform-module-upgrade-demo-harnessrepo2
                      GITHUB_OWNER: gregkroonorg
                      GITHUB_APP_ID: "1234"
                      GITHUB_INSTALLATION_ID: "1234"
                      GITHUB_PRIVATE_KEY: <+secrets.getValue("githubapppem")>
                      GIT_AUTHOR_NAME: gregkroon
                      GIT_AUTHOR_EMAIL: blah@users.noreply.github.com
                      AUTO_MERGE: "true"
```

Trigger this pipeline on a recurring schedule (e.g., weekly) to check and upgrade all referenced modules.

## 🔄 High-Level Workflow

This is how the system works end-to-end:

### 1. **Publish a New Module Version**

* Commit changes to a Terraform module repo
* Tag the new release:

  ```bash
  git tag v1.2.3
  git push origin v1.2.3
  ```

### 2. **Sync Harness IACM Module Registry**

* Harness periodically or manually syncs the registry with new module versions

### 3. **Scheduled Upgrade Pipeline**

* A Harness pipeline runs daily/weekly via **cron trigger**
* Executes this bot in a Docker container
* Scans defined GitHub repos for outdated Terraform modules

### 4. **Pull Request Flow**

* Bot creates PRs for modules with version upgrades:

  * Minor/patch upgrades are batched
  * Major upgrades have separate PRs
* PRs trigger Harness CI/CD pipelines via GitHub Webhook

### 5. **Pipeline Validation**

* Harness pipeline:

  * Runs `terraform init`, `plan`, and `apply` (dry run)
  * Performs static analysis via Checkov or Terrascan
  * Optionally requires manual approval
* PR is auto-merged if all checks pass

### 6. **Production Promotion**

* A second stage can trigger a promotion pipeline to apply module upgrades to production environments
