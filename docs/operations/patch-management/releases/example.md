# Example: Production release — 2025-07-07

> Based on the historical release record. Missing details are marked “Not recorded.”

## Summary

| Field | Details |
| --- | --- |
| Change / ticket | [Issue #25](https://github.com/ADORSYS-GIS/wazuh-helm/issues/25), [issue #23](https://github.com/ADORSYS-GIS/wazuh-helm/issues/23) |
| Owner | Armand Meppa (listed as Dev Contact) |
| Target version | Not recorded |
| Affected services | Wazuh Manager, Indexer, Dashboard, Jira integration |
| Reason for change | Fix Jira integration and reimplement false-positive rules |
| Planned window / expected impact | 2025-07-07, 11:00 (UTC+1); 5–10 minutes downtime expected |

## Approval

- **Approver and date:** Wazuh team; date not recorded
- **Approval link:** Not recorded

## Deployment

- **Deployer and deployment time:** Not recorded
- **Pipeline / Argo CD run:** Not recorded
- **Recorded deployment plan** (completion was not recorded):
  - [ ] Confirm approval and deployment window
  - [ ] Back up the production cluster
  - [ ] Update Wazuh `targetVersion` in Argo CD and deploy
  - [ ] Check cluster health after deployment
  - [ ] Test Jira integration
  - [ ] Test false-positive rules
  - [ ] Run system checks and record any deviations
- **Deviations:** Not recorded

## Validation

- **Recorded validation plan** (results were not recorded):
  - [ ] Wazuh dashboard is accessible
  - [ ] Manager, indexer, and dashboard are healthy
  - [ ] Jira integration works in production
  - [ ] False-positive rules behave as expected
  - [ ] No unexpected errors or alerts appear in logs
- **Evidence links:** Not recorded
- **Outcome:** Not recorded

## Rollback and closeout

- **Rollback trigger and steps:** Trigger not recorded. Plan: revert to the last stable deployment and disable the new rules if needed; estimated 15–25 minutes.
- **Rollback performed / result:** Not recorded
- **Stakeholders notified:** `#wazuh-team` listed; completion not recorded
- **Follow-up actions / owners:** Not recorded
- **Record closed by / date:** Not recorded
