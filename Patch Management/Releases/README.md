# Production release process

Use this process for every Wazuh production release. It records who approved the change, what was deployed, and whether it worked. It supports ISO/IEC 27001 change control; it is not an ISO certification statement.

1. Copy [`template.md`](template.md) to `YYYY-MM-DD.md`. Add the change ID to the filename if there is more than one release that day.
2. Record the change ID, affected services, reason, exact release version, risks, test results, backup, deployment steps, and rollback steps. Link to the issue, pull request, tests, and release artifact.
3. Get and record approval before deployment. The person deploying must not be the only approver. Do not proceed with unresolved review comments or unaccepted risks.
4. Deploy the reviewed and tested version during the approved window. Record who deployed it, when, the pipeline or Argo CD run, and any deviation.
5. Run the validation checks and record results with evidence links. If checks fail or a rollback trigger is met, follow the rollback plan and record the outcome.
6. Notify stakeholders, assign follow-up actions, and close the record. Keep evidence in approved access-controlled systems; never add credentials or secrets to these files.

Use the [Wazuh cluster upgrade playbook](../wazuh-cluster-update.md) for the technical deployment steps. Keep older release records as written; add a dated note if audit context is missing rather than changing past history.
