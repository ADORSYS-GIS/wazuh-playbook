# 🔒 Patch Management Process - Wazuh SIEM/SOC Platform

## 🧠 Overview

This document outlines the **patch management process** for the Wazuh SIEM/SOC infrastructure. It includes the main Wazuh stack, agents, and complementary tools like **YARA**, **Suricata**, and **Snort**. The **SIEM/SOC team** is responsible for orchestrating this process using GitHub Projects and a Dev/Prod cluster architecture.

---

## 📅 Patch Frequency

- **Every Thursday**
- Applies to:
  - Wazuh Manager, Dashboard, Indexer, Monitoring tools, ArgoCD
  - Wazuh Agent
  - Complementary tools: YARA, Suricata, Snort, Wazuh-cert-oauth, Wazuh-agent-status
- Managed via **GitHub Projects Kanban Board**

---

## 🧾 Pre-Patch Prerequisites (Every Wednesday EOD)

| Task | Description | Owner |
|------|-------------|-------|
| 🔍 Review Upstream Releases | Check for new versions, rules, CVEs, configs | SIEM/SOC Team |
| 📂 Create GitHub Issues | One issue per patch | SIEM/SOC Team |
| 🧪 Patch in Dev Cluster | Deploy updates in dev environment | SIEM/SOC Team |
| ✅ Run CI/CD Pipelines | Validate syntax, rules, signatures, alerts | SIEM/SOC Team |
| 📋 Update GitHub Board | Move issues through appropriate stages | SIEM/SOC Team |

---

## 🧱 GitHub Projects Workflow

The following Kanban board stages should be used for all patch activities:

| Stage | Description |
|-------|-------------|
| ✅ **Ready** | Issue is created and ready to be worked on |
| 🟡 **In progress** | Patch is being developed or updated |
| 🟣 **In review** | Undergoing peer review in a Pull Request |
| 🟡 **Deploy in Dev** | Merged and deployed in dev cluster for testing |
| 🟣 **PO_Review** | SIEM/SOC lead validates functionality |
| 🔵 **Approved for Production** | Ready to be released to production |
| 🟢 **Deploy in prod** | Patch has been successfully deployed |

---

## 📦 Per-Repository Release Strategy

Each repo maintains its own versioning and changelogs.

### 🔹 Our Repos

- `wazuh`
- `wazuh-helm`
- `wazuh-agent`
- `wazuh-cert-oauth`
- `wazuh-agent-status`
- `wazuh-yara`
- `wazuh-suricata`
- `wazuh-snort`

### 🔖 Tagging Convention

```

v<major>-<minor>-<patch>
e.g. v0.6.2

````
#### where: 

**Major release version:** If there are any major changes in a package, such as breaking modifications or new features, a release is made by upgrading this major version number.

**Minor release version:** If any modifications are made that are backward-compatible or deprecate any functionality, a release is made by changing this minor version number.

**Patch release version:** If just bug fixes are included, a release is completed by updating this minor version number.

### 📄 Release Notes

Each repo should include:
- Version diff
- Compatibility info (OS)
- Validation/test results
- Manual runbooks if applicable

### 🔗 Composite Release

The `wazuh-agent` repo includes a combined release referencing the tools:


---

## 🚀 Thursday Patch Day Schedule

| Time  | Task                                       |
| ----- | ------------------------------------------ |
| 09:00 | Trigger CI/CD for merged/approved issues   |
| 10:00 | Canary deployment to 10% of prod agents    |
| 13:00 | Expand rollout to 50% of production        |
| 16:00 | Full rollout to all agents/clusters        |
| 17:00 | Final validation; log patch events in SIEM |

---

## 🔄 Rollback Procedure

Rollback criteria:

* Major failure in connectivity/alerts
* Regression detected in complementary tools

Rollback steps:

1. Use previous release artifacts from GitHub
2. Re-deploy previous version via CI/CD
3. Log rollback as incident in SIEM
4. Update GitHub issue with `rolled-back` label

---

## 📊 Post-Patch Reporting

Every Friday, a report is generated (automated or manually) with:

* Tools/agents updated
* Issues/PRs closed
* Version distribution graph
* Any rollback or known issues
* Link to dashboards/logs with patch activity

---

## ✅ Best Practices

* Patch only with validated releases
* Always validate rules/tools against test PCAPs or logs
* Keep GitHub release notes concise and auditable
* Track coverage with dashboards (agent version compliance)
* Use GitHub Actions for consistent tagging and release flows
* Retain a rollback version history of at least 3 weeks

---

## 👥 Roles and Responsibilities

| Role          | Task                                                         |
| ------------- | ------------------------------------------------------------ |
| SIEM/SOC Team | Full ownership of patch creation, validation, and deployment |
| Team Lead     | Validates in PO\_Review stage and approves for prod          |
| CI/CD Bot     | Handles auto-deploy, notifications, version tagging          |

---

