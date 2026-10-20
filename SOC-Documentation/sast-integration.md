# Static Application Security Testing (SAST) Integration Guide
**Wazuh Ecosystem Central Specification & Compliance Manual**

> **Document Status**: Approved  
> **Target Audience**: SIEM Engineers, Wazuh Contributors, Security Auditors  
> **Source**: Centralized Wazuh Security Operations

---

# SAST Integration Wazuh Ecosystem

## 1. What is SAST?

Static Application Security Testing (SAST) is a type of security testing that analyzes an application's source code, bytecode, or binaries without executing the application. It is sometimes called "white-box testing" because the scanner has full visibility into the code being analyzed.

SAST tools work by parsing the code and applying a set of rules, patterns, and data-flow analyses to detect security weaknesses. They look for things like:

- Injection flaws: SQL injection, command injection, LDAP injection, XSS.
- Insecure deserialization and path traversal.
- Hardcoded secrets: passwords, API keys, tokens left in source.
- Weak cryptography: weak hashing algorithms, insecure random number generation.
- Insecure configuration: overly permissive permissions, missing security headers.
- Unsafe dependencies / API misuse calling dangerous functions or libraries incorrectly.
- Resource leaks and error-handling flaws that could be exploited.

Because SAST runs on the code itself, it can find issues early in the software development lifecycle (SDLC), ideally at the moment a developer writes or commits code , which is far cheaper and safer to fix than discovering them in production.

### Why SAST matters

- Shift-left security. SAST moves security testing to the earliest possible point in the pipeline, catching vulnerabilities before they reach build, test, or production environments.
- Cost reduction. Fixing a vulnerability during development costs a fraction of fixing it after deployment. Industry data consistently shows that defects found early are dramatically cheaper to remediate.
- Comprehensive coverage. Unlike dynamic testing, SAST can inspect every code path, including ones that are hard to reach at runtime, and can analyze code that isn't even executed yet.
- Developer feedback. Integrated into CI, SAST gives developers immediate, inline feedback on the exact line of code that needs attention.
- Compliance. Many standards (OWASP Top 10, CWE Top 25, PCI DSS, OWASP ASVS, STIG) require evidence of static analysis. SAST provides auditable scan results.
- Consistency and scale. Automated scans apply the same security bar to every repository, removing reliance on manual code review alone.

### SAST vs. DAST vs. IAST

| Type | Name | How it works | When it runs |
| --- | --- | --- | --- |
| SAST | Static Application Security Testing | Analyzes source code without executing it (white-box) | Early in development, typically during development or CI. |
| DAST | Dynamic Application Security Testing | Tests a running application from the outside (black-box) | Later in the lifecycle, against running applications in test or deployed environments. |
| IAST | Interactive Application Security Testing | Instruments the running app and observes behavior in real time | During application testing, from inside the running application. |

Note on scope: DAST and IAST are not yet supported and document focuses only on SAST.

## 2. Overview of the integration

SAST is integrated into the CI/CD pipelines of the adorsys Wazuh ecosystem. Scans run automatically on pull requests and pushes, analyzing first-party code for security vulnerabilities before it is merged and deployed.

The integration is built on the shared, reusable templates in adorsys-ci-cd-templates, so every consuming repository gets the same security bar without maintaining its own pipeline logic. Each scanner is opt-in and additive, so existing pipelines are unaffected.

### Goals

- Automatically detect security vulnerabilities in first-party code during CI.
- Surface findings to developers inline on pull requests for fast remediation.
- Enforce a severity-based gate on protected branches so High/Critical findings cannot be merged.
- Provide SonarQube as the primary code-quality and security gate, including compliance-standard reporting.
- Reuse a single, maintained set of templates across all repositories for consistency.

### Non-goals / out of scope

- DAST and IAST (tracked separately under #549).
- Scanning of third-party/vendored code beyond what the scanners detect by default.
- Replacing manual security code review, SAST complements, not replaces, human review.

## 3. Architecture

![image-20261013-175525.png](images/image-20261013-175525.png)

## 4. Tools used

| Tool | Purpose | Reusable workflow |
| --- | --- | --- |
| SonarQube | Full-branch static analysis; gates on bugs/vulnerabilities, BLOCKER/CRITICAL/MAJOR severity, and compliance standards | sonarqube.yml |
| Checkov | IaC scanning (Terraform / Helm) | sast-iac.yml |
| ShellCheck | Shell scripts (*.sh, *.bash, *.zsh) | sast-shell.yml |
| Semgrep | Multi-language scanning (auto-detect) | sast-semgrep.yml |
| Bandit | Python | sast-python.yml |
| Gosec | Go | sast-go.yml |
| Clippy + Semgrep | Rust | sast-rust.yml |
| PSScriptAnalyzer | PowerShell | sast-powershell.yml |
| ESLint | JavaScript / TypeScript (eslint-plugin-security) | sast-javascript-typescript.yml |
| reviewdog | Surfaces SARIF findings as PR/commit check annotations | reviewdog |

### SonarQube : The primary gate

SonarQube is the primary code-quality and security gate. It performs full-branch analysis (never PR-diff-only), so pre-existing issues surface as well as new ones. It enforces three independent gate conditions:

- Any unresolved bug or vulnerability (any severity).
- Any BLOCKER / CRITICAL / MAJOR issue (any type, including code smells).
- Any issue mapped to a configured compliance standard: OWASP Top 10 2021 CWE Top 25 2024 PCI DSS 4.0 OWASP ASVS 4.0 STIG ASD V5R3 CASA

Former Security Hotspots are now raised as vulnerabilities, so they are covered by the type condition ; no separate hotspot query is needed.

### Scanner selection by language

The wazuh repository itself uses Checkov (IaC) and ShellCheck (shell), plus SonarQube. Other repositories select the scanners that match their technology stack:

| Language / technology | Scanner |
| --- | --- |
| Terraform / Helm (IaC) | Checkov |
| Shell (*.sh, *.bash, *.zsh) | ShellCheck |
| Python | Bandit |
| Go | Gosec |
| Rust | Clippy + Semgrep |
| PowerShell | PSScriptAnalyzer |
| JavaScript / TypeScript | Semgrep + ESLint |
| Java | Semgrep |

## 5. How it works

- A PR or push to a protected branch triggers the SAST workflow(s).
- Each scanner runs against the repository and emits results as SARIF 2.1.0.
- reviewdog converts the SARIF into check annotations on the PR (or commit for pushes), so developers see findings inline ; including pre-existing findings in any file the PR touches.
- SonarQube runs a full-branch analysis and enforces the quality gate.
- On protected branches, High/Critical findings fail the build; on feature branches, findings are advisory only.

### Example caller workflow (.github/workflows/sast.yml )

### Example SonarQube workflow (.github/workflows/sonarqube.yml )

## 6. Gating policy

| Context | Behavior |
| --- | --- |
| Feature branches | Advisory ; scans run with continue-on-error / allow_failure; findings are reported as annotations but do not block the PR. |
| Protected branches (develop, main, master) | Hard-fail on High/Critical findings (SARIF severity error) in files the PR touches. |
| SonarQube | Fails on unresolved bugs/vulnerabilities, BLOCKER/CRITICAL/MAJOR issues, and compliance-standard findings. |
| Scanner crash / no-op | Reported as a step failure regardless of findings (guards against silent false-green). |

### Why advisory on feature branches?

During the integration phase, strict gating on feature branches would have blocked ongoing work on repositories with pre-existing findings. Advisory mode lets developers see and fix findings without being blocked, while protected branches still enforce the security bar before anything reaches production.

Rollout note: the gate was integrated with advisory behavior first so ongoing work was not blocked during the integration phase. Now that integration is complete, repositories with pre-existing findings may see workflow failures; follow-up tickets track remediation per repository.

## 7. Repositories integrated

| Repository | PR |
| --- | --- |
| wazuh-yara | #96 |
| wazuh-agent-status | #248 |
| wazuh-suricata | #50 |
| wazuh-cert-oauth2 | #348 |
| wazuh-agent-installer | #28 |
| wazuh | #2167 |
| wazuh-helm | #456 |
| wazuh-agent | #257 |
| wazuh-plugins | #16 |
| global-gateway | #12 |

## 8. SonarQube setup

- Repository secrets: SONAR_HOST_URL, SONAR_TOKEN.
- Repository variable: SONAR_PROJECT_KEY (the project must already exist in SonarQube).
- Full-branch analysis: the workflow analyses the whole source branch (sonar.branch.name), not just the PR diff.
- Quality gate: polled via the SonarQube API (not qualitygate.wait), with a configurable analysis-timeout (default 300s) and retries on transient failures.
- Optional inputs: source-dirs, exclusions, test-dirs, coverage-report-paths, fail-types, fail-severities, compliance-filters.

## 9. Results & accessibility

- PR check annotations: via reviewdog, visible directly on the pull request.
- SonarQube: full findings and compliance reports in the SonarQube server UI.
- SARIF artifacts: raw scan results retained for audit.
- No GitHub Advanced Security / CodeQL upload is required, so no paid GHAS entitlement is needed on private repos.

## 10. Onboarding sast onto a new repository

To add SAST to a new repository:

- Add a caller workflow .github/workflows/sast.yml referencing the relevant sast-*.yml templates for your stack.
- Add .github/workflows/sonarqube.yml and configure SONAR_HOST_URL / SONAR_TOKEN secrets and the SONAR_PROJECT_KEY variable.
- Ensure the project key exists in SonarQube.
- Open a PR; verify the scans run and findings appear as annotations.
- Triage any pre-existing findings (start advisory, tighten the gate once a clean baseline is reached).

## 11. References

- Reusable templates: adorsys-ci-cd-templates
- Parent ticket: wazuh#549

+
