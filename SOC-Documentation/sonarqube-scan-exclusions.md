# SonarQube Scan Exclusions across Wazuh Solutions
**Wazuh Ecosystem Central Specification & Compliance Manual**

> **Document Status**: Approved  
> **Classification**: Internal / ISO 27001 Operational Baseline  
> **Target Audience**: SIEM Engineers, Wazuh Contributors, Security Auditors  
> **Source**: Centralized Wazuh Security Operations

---

## Overview

This page documents the files and directories excluded from SonarQube issue analysis across Wazuh projects.

When a file is excluded through `sonar.exclusions`, SonarQube does not report bugs, vulnerabilities, or code smells for that file as part of the scan. This is different from `sonar.coverage.exclusions`, which only affects code coverage metrics. Files excluded from coverage are still scanned for issues.

All Wazuh projects use the shared [GitHub Actions workflow](https://github.com/ADORSYS-GIS/adorsys-ci-cd-templates). Each repository can pass an `exclusions` input, which is forwarded to the scanner as `-Dsonar.exclusions`.

**Guiding principle:** Only exclude code that we do not maintain ourselves, such as generated code, third-party dependencies, and build artifacts. Hand-written source code should remain part of the scan.

## 1. wazuh-agent-status

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-agent-status/blob/main/.github/workflows/sonarqube.yml)

This project is a Rust service with a React frontend.

| Excluded pattern | Reason |
| --- | --- |
| **/target/** | Rust and Cargo build output, including the Tauri src-tauri/target directory. |
| **/node_modules/** | Third-party npm packages. |
| **/dist/** | Frontend build output. |
| **/coverage/** | Generated coverage reports and artifacts. |

## 2. wazuh-cert-oauth2

**Configuration:** [ci.yml](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/blob/main/.github/workflows/ci.yml)

This project is a Rust workspace.

| Excluded pattern | Reason |
| --- | --- |
| **/target/** | Rust and Cargo build output. |
| _site/** | Jekyll build output. |
| lcov.info | Generated coverage report file. |

## 3. wazuh-gateway

**Configuration:** [ci.yml](https://github.com/ADORSYS-GIS/wazuh-gateway/blob/main/.github/workflows/ci.yml)

This project is a Rust service.

| Excluded pattern | Reason |
| --- | --- |
| **/target/** | Rust and Cargo build output. |
| **/node_modules/** | Third-party npm packages. |
| **/dist/** | Frontend build output. |
| **/coverage/** | Generated coverage reports and artifacts. |

## 4. wazuh-agent-installer

**Configuration:** [ci.yml](https://github.com/ADORSYS-GIS/wazuh-agent-installer/blob/develop/.github/workflows/ci.yml)

This project is a Rust/Tauri desktop application with a TypeScript and Vite frontend.

| Excluded pattern | Reason |
| --- | --- |
| **/target/** | Rust and Cargo build output. |
| **/node_modules/** | Third-party npm packages. |
| **/dist/** | Frontend build output. |
| **/coverage/** | Generated coverage reports and artifacts. |

## 5. wazuh-plugins

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-plugins/blob/main/.github/workflows/sonarqube.yml)

This project includes Python tooling used for building and testing.

| Excluded pattern | Reason |
| --- | --- |
| **/coverage/** | Generated coverage reports and artifacts. |
| **/__pycache__/** | Python bytecode caches. |
| **/venv/** | Python virtual environments and their installed dependencies. |
| **/.venv/** | Python virtual environments and their installed dependencies. |
| tests/** | Test suites and test fixtures. |

## 6. wazuh-yara

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-yara/blob/main/.github/workflows/sonarqube.yml)

This project contains Shell and PowerShell installers, along with Python test tooling.

| Excluded pattern | Reason |
| --- | --- |
| **/coverage/** | Generated coverage reports and artifacts. |
| **/__pycache__/** | Python bytecode caches, for example under scripts/tests/__pycache__ . |

The Shell, PowerShell, and BATS code itself remains part of the scan wherever applicable.

## 7. wazuh-suricata

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-suricata/blob/main/.github/workflows/sonarqube.yml)

This project contains Shell and PowerShell installers, along with a BATS test suite.

| Excluded pattern | Reason |
| --- | --- |
| **/coverage/** | Generated coverage reports and artifacts. |

The Shell, PowerShell, and BATS source code remains part of the scan.

## 8. global-gateway

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/global-gateway/blob/main/.github/workflows/sonarqube.yml)

This project contains Infrastructure as code, including Terraform and Ansible for deploying and configuring netbird, along shell scripts, and python scripts.

| Excluded pattern | Reason |
| --- | --- |
| **/.terraform.lock.hcl | Terraform dependency lock files. |
| **/.claude/** | AI agent tooling configuration and cache. |
| .scannerwork/** | SonarScanner internal working directory and analysis cache. |
| **/__pycache__/** | Python bytecode caches. |
| **/*.pyc | Compiled Python bytecode files. |
| docs/** | Markdown documentation. |

## 9. wazuh-agent

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-agent/blob/main/.github/workflows/sonarqube.yml)

This project contains installation and configuration scripts written in Shell and PowerShell, alongside BATS test suites.

| Excluded pattern | Reason |
| --- | --- |
| **/coverage/** | Generated coverage reports and artifacts (e.g. `coverage/sonar-coverage.xml`). |

*Note*: Test scripts, OS-specific files, and helper scripts are handled under coverage exclusions (`extra-sonar-args: -Dsonar.coverage.exclusions=...`) rather than general issue analysis exclusions.

## 10. wazuh-trivy

**Configuration:** [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-trivy/blob/main/.github/workflows/sonarqube.yml)

This project integrates Trivy vulnerability scanning into the Wazuh security pipeline.

| Excluded pattern | Reason |
| --- | --- |
| **/coverage/** | Generated coverage reports and artifacts. |

## 11. Projects Using Shared Template Defaults

The following repositories do not override the shared workflow's `exclusions` input and therefore use its default exclusion patterns:

`**/node_modules/**, **/dist/**, **/build/**, **/coverage/**`

| Project | SonarQube configuration | Project contents |
| --- | --- | --- |
| wazuh | [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh/blob/main/.github/workflows/sonarqube.yml) | Infrastructure as code, including Terraform and ArgoCD, plus Shell scripts. |
| wazuh-helm | [sonarqube.yml](https://github.com/ADORSYS-GIS/wazuh-helm/blob/main/.github/workflows/sonarqube.yml) | Helm charts and Python tooling. |

These defaults are intended to exclude dependencies, generated output, and build artifacts rather than hand-written project source code.

## 12. wazuh-playbook

The `wazuh-playbook` repository contains documentation and is not currently scanned by SonarQube.

| Item | Status |
| --- | --- |
| SonarQube scan | Not configured |
| sonar.exclusions | Not applicable |
| Reason | The repository contains documentation and is not included in the SonarQube scan. |

## 13. Shared CI Template Defaults

There are two default configurations to distinguish:

| Configuration | Default exclusion patterns |
| --- | --- |
| Shared reusable workflow | **/node_modules/**, **/dist/**, **/build/**, **/coverage/** |
| SONAR_EXCLUSIONS used by projects running SonarScanner CLI without overriding the variable | **/node_modules/**, **/dist/**, **/build/**, **/coverage/**, **/target/** |

These patterns target third-party dependencies, generated output, and build artifacts. They help reduce irrelevant findings while keeping hand-written source code in scope.

Repository-specific overrides may differ from these defaults. The effective exclusions should therefore be checked in the relevant workflow or scanner configuration.

## 14. Guidelines for Maintaining Exclusions

| Guideline | Description |
| --- | --- |
| Exclude only what is necessary | Use sonar.exclusions for generated code, third-party dependencies, and build artifacts that should not be analyzed. |
| Keep hand-written source code in scope | Do not exclude source files merely to suppress bugs, vulnerabilities, or code smells. |
| Use coverage exclusions appropriately | Use sonar.coverage.exclusions when files should be omitted from coverage metrics but remain subject to issue analysis. |
| Document every exclusion | Each exclusion pattern should have a clear, justifiable reason. |
| Keep exclusions consistent | Similar projects should use consistent patterns where their technology stacks and build structures are comparable. |
| Review changes | When adding or changing an exclusion, verify that it does not unintentionally remove maintained source code from analysis. |

The three Rust / Tauri projects (`wazuh-agent-status`, `wazuh-gateway`, `wazuh-agent-installer`) share the standard Rust exclusion set:

`**/target/**, **/node_modules/**, **/dist/**, **/coverage/**`

This keeps their configurations consistent while excluding their build output, frontend dependencies, and coverage artifacts. For `wazuh-cert-oauth2`, the exclusion list additionally covers Jekyll site output (`_site/**`) and its coverage report (`lcov.info`).

## Summary

This page provides an overview of the documented SonarQube scan exclusions across Wazuh Solutions. The intention is to keep exclusions minimal, consistent, and justified, while ensuring that hand-written source code remains subject to SonarQube issue analysis.

When a new exclusion is introduced or an existing pattern changes, update this page to reflect the effective configuration and the reason for the change.
