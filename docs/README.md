# wazuh-playbook Documentation

The `wazuh-playbook` repository contains playbooks designed to assist in remediating security incidents detected by Wazuh. Each playbook provides a structured approach to handling various threats, supporting both automated and manual response strategies.

## SDLC map

| Phase | Folder | Contents |
| :---- | :----- | :------- |
| Development | [`development/`](development/) | CI/CD tooling: SAST integration, SonarQube scan exclusions |
| Operations | [`operations/`](operations/) | Deploy/runbooks/incidents: auditd, vulnerability detection, agent migration, patch management, dashboards, incidents |
| Reference | [`reference/`](reference/) | Cross-cutting references: compliance (CIS benchmarks), FIM, MITRE ATT&CK, Docker/YARA rules, playbook template |

## Quick links

| Link | Description |
| :--- | :---------- |
| [SAST Integration Guide](development/sast-integration.md) | Static Application Security Testing integration into CI/CD |
| [SonarQube Scan Exclusions](development/sonarqube-scan-exclusions.md) | Scan exclusions across Wazuh solutions |
| [Auditd Integration](operations/Auditd_integration.md) | Auditd rules and event collection |
| [Vulnerability Detection](operations/Vulnerability-dect.md) | Vulnerability detection playbook |
| [OTA Agent Update](operations/OTA_AGENT_UPDATE.md) | Over-the-air agent update |
| [Wazuh Agent Migration](operations/WAZUH_AGENT_MIGRATION.md) | Agent migration playbook |
| [Wazuh Cluster Update](operations/patch-management/wazuh-cluster-update.md) | Cluster update / patch management |
| [Release Notes](operations/patch-management/releases/README.md) | Historical release records |
| [Incident Playbooks](operations/incidents/Incident-event.md) | Incident event handling |
| [SOC Concept](operations/incidents/SOC-concept.md) | SOC operating concept |
| [Dashboards](operations/dashboards/) | Importable dashboards (`.ndjson`) |
| [Docker Security Rules](reference/Docker-Security-Rules.md) | Docker security rule reference |
| [YARA Rules](reference/yara_rules.md) | YARA rule reference |
| [FIM](reference/fim/) | File integrity monitoring reference |
| [MITRE ATT&CK](reference/mitre-attack/) | MITRE ATT&CK techniques and rules |
| [Compliance (CIS)](reference/compliance/Version_Matrix.md) | CIS benchmark version matrix |
| [Playbook Template](reference/playbook-template.md) | Reusable playbook template |
