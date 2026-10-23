# Production release record

> Copy this file to `YYYY-MM-DD.md` (add the change ID if there is more than one release that day). Complete it before deployment. Link to evidence; never include credentials or secrets.

## Release details

| Field | Details |
| --- | --- |
| Change ID / ticket | |
| Release date | YYYY-MM-DD |
| Release owner | |
| Target environment | Production |
| Affected services / agents | |
| Current version → target version | |
| Reason for change | |
| Release / pull request links | |
| Expected impact / downtime | |

## Readiness

| Check | Evidence / details |
| --- | --- |
| Security risks and mitigations | |
| Test environment and results | |
| Review and scan results | |
| Backup or recovery point | |
| Monitoring / dashboard | |
| Rollback trigger | |
| Rollback steps and estimated time | |

## Approval

| Approver and role | Decision | Date/time and timezone | Evidence link |
| --- | --- | --- | --- |
| | | | |

Record approval before deployment. The deployer cannot be the only approver. For any check that does not apply, enter `N/A` and explain why.

## Deployment

| Field | Details |
| --- | --- |
| Approved window | |
| Deployer(s) | |
| Pipeline / Argo CD run | |
| Actual start / end time | |
| Steps performed | |
| Deviations and reason | |

## Validation and closeout

| Check | Expected result | Result | Evidence link |
| --- | --- | --- | --- |
| Manager, indexer, and dashboard | Healthy; target versions active | | |
| Agent connectivity and event flow | Expected agents reporting; events flowing | | |
| Changed rules or integrations | Expected behavior confirmed | | |
| Alerts, errors, and performance | No unexplained critical issues | | |

| Closeout | Details |
| --- | --- |
| Release outcome | Successful / Rolled back / Partially successful |
| Rollback performed | Yes / No; details and evidence |
| Stakeholders notified | Who, when, and link |
| Open issues and owners | |
| Record closed by / date | |
| Evidence location | Approved access-controlled system |
