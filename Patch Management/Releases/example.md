# Example: Production release record

> Example based on the historical 2025-07-07 release record. Missing execution evidence is marked **Not recorded**; it has not been inferred. Use `template.md` for new releases.

## Release details

| Field | Details |
| --- | --- |
| Change ID / ticket | Wazuh Helm issues [#25](https://github.com/ADORSYS-GIS/wazuh-helm/issues/25) and [#23](https://github.com/ADORSYS-GIS/wazuh-helm/issues/23) |
| Release date | 2025-07-07 |
| Release owner | Armand Meppa (listed as Dev Contact) |
| Target environment | Production |
| Affected services / agents | Wazuh Manager, Indexer, Dashboard, and Jira integration service |
| Current version → target version | Not recorded |
| Reason for change | Fix Jira integration in production and reimplement custom false-positive rules to reduce alert noise |
| Release / pull request links | [Jira integration fix](https://github.com/ADORSYS-GIS/wazuh-helm/commit/9c0a6d8bd8b0c53f261ed3da1a081a61ad99ea33); [false-positive rules](https://github.com/ADORSYS-GIS/wazuh-helm/commit/fcd2fde377f32c1c7c43f6fd4498dbd85ea4f5a8) |
| Expected impact / downtime | Approximately 5–10 minutes for service restart |

## Readiness

| Check | Evidence / details |
| --- | --- |
| Security risks and mitigations | Not recorded |
| Test environment and results | Historical record says Jira integration and false-positive rules were to be tested; results not recorded |
| Review and scan results | Code review approval and scan evidence not recorded |
| Backup or recovery point | Not recorded |
| Monitoring / dashboard | Production dashboard: https://wazuh.adorsys.team/ |
| Rollback trigger | Not recorded |
| Rollback steps and estimated time | Revert to last stable deployment; disable new false-positive rules if needed. Estimated 15–25 minutes. |

## Approval

| Approver and role | Decision | Date/time and timezone | Evidence link |
| --- | --- | --- | --- |
| Wazuh team | Approved (as stated in historical record) | Not recorded | Not recorded |

## Deployment

| Field | Details |
| --- | --- |
| Approved window | 2025-07-07 at 11:00 (UTC+1) |
| Deployer(s) | Not recorded |
| Pipeline / Argo CD run | Historical plan: update Wazuh `targetVersion` in Argo CD. Run link and completion not recorded. |
| Actual start / end time | Not recorded |
| Steps performed | Historical plan: back up production; update Wazuh `targetVersion`; validate cluster health; verify Jira integration and false-positive rules; run system tests. Completion not recorded. |
| Deviations and reason | Not recorded |

## Validation and closeout

| Check | Expected result | Result | Evidence link |
| --- | --- | --- | --- |
| Manager, indexer, and dashboard | Healthy; target versions active | Not recorded | Not recorded |
| Agent connectivity and event flow | Expected agents reporting; events flowing | Not recorded | Not recorded |
| Changed rules or integrations | Jira test ticket created; false-positive rules behave as expected | Not recorded | Not recorded |
| Alerts, errors, and performance | No unexplained critical issues | Not recorded | Not recorded |

| Closeout | Details |
| --- | --- |
| Release outcome | Not recorded |
| Rollback performed | Not recorded |
| Stakeholders notified | Historical record lists `#wazuh-team`; notification completion not recorded |
| Open issues and owners | Not recorded |
| Record closed by / date | Not recorded |
| Evidence location | Historical record in this folder; supporting evidence not linked |
