# ✅ Deploy to Production Request

---

## 📌 Summary

Deployment of Wazuh security incident management system upgrade including new incident event management capabilities, platform upgrade to v4.12, and additional false positive rules to reduce noise in alerts.

---

## 📦 Change Description

- Feature(s) / Fix(es):
  - [https://github.com/ADORSYS-GIS/wazuh-helm/issues/15] Implement incident event management system in Wazuh
  - [https://github.com/ADORSYS-GIS/wazuh/issues/220] Upgrade Wazuh platform to v4.12
  - [https://github.com/ADORSYS-GIS/wazuh-helm/issues/23] Add false positive rules to reduce alert noise

- Code Repository: [https://github.com/orgs/ADORSYS-GIS/projects/10/views/1]
- Related Commits / Merge Requests:
  - [https://github.com/ADORSYS-GIS/wazuh-helm/commit/14bc435c00848ac52cd2b1d389b9dc5cd82af3eb] Incident management configuration
  - [https://github.com/ADORSYS-GIS/wazuh-helm/commit/14bc435c00848ac52cd2b1d389b9dc5cd82af3eb] Wazuh v4.12 upgrade scripts
  - [https://github.com/ADORSYS-GIS/wazuh-helm/commit/b77b7497d893c489f800f98ac30fd2e93c9b8e2f] False positive ruleset
---

## 🗂️ Environment

- **Target Environment:** Production
- **Affected Services:** 
  - Wazuh Manager
  - Wazuh Indexer
  - Wazuh Dashboard
  - Security Monitoring API

- **Environment URLs:**
  - Dev: https://dev.wazuh.adorsys.team/app/wz-home#/overview/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&_a=(filters:!(),query:(language:kuery,query:''))

  - Production: https://wazuh.adorsys.team/app/wz-home#/overview/?agentId=069&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&_a=(filters:!(),query:(language:kuery,query:''))

---

## 🧪 Pre-Deployment Checklist

- [ ] Code reviewed and approved
- [ ] All tests passed (unit, integration, e2e)
- [ ] Manual QA passed on staging
- [ ] Infrastructure changes tested
- [ ] Security scans passed (e.g. Snyk, Trivy)
- [ ] Cost impact validated (if applicable)
- [ ] Downtime expected? If yes, stakeholders informed

---

## 📅 Deployment Plan

1. Trigger CI/CD deployment pipeline: [link]
2. Apply Terraform changes (if any)
3. Run DB migrations (if needed)
4. Enable feature flags (if applicable)
5. Perform smoke test on production
6. Validate system health via dashboards and logs

---

## 🧯 Rollback Plan

- Revert to last stable deployment
- Rollback Terraform (if infra changed)
- Restore previous ruleset configuration
- Disable feature flags
- Notify stakeholders
- Time estimate for rollback: _e.g., 15 minutes_

---

## 👥 Stakeholders & Notifications

- **Dev Contact:** @dev-username
- **QA Contact:** @qa-username
- **Product Owner:** @product-owner
- **Security Team:** @security-ops
- **Slack Channel Notification:** #prod-deploys

---

## 🕐 Deployment Window

- **Scheduled Date & Time:** 2025-06-23 @ 13:00 (UTC)
- **Approved by:** 

---

## ✅ Post-Deployment Validation

- [ ] Wazuh dashboard accessible and functioning

- [ ] Incident events being properly logged

- [ ] Version 4.12 confirmed on all components

- [ ] False positive rules reducing alert volume as expected

- [ ] Security dashboards show normal behavior

- [ ] Alerts and logs reviewed for anomalies

- [ ] Confirmation sent to stakeholders