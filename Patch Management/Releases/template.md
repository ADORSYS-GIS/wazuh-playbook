# ✅ Deploy to Production Request

---

## 📌 Summary

> Brief description of the feature/fix being deployed and the reason for the deployment.

---

## 📦 Change Description

- Feature(s) / Fix(es):
  - [JIRA-XXX] Feature X
  - [MR#123] Fix Y
- Code Repository: [link]
- Related Commits / Merge Requests: [link]

---

## 🗂️ Environment

- **Target Environment:** Production
- **Affected Services:** e.g. Backend API, Frontend, Lambda Functions
- **Environment URLs:**
  - Staging: https://staging.example.com
  - Production: https://prod.example.com

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
- Rollback DB schema (if migration was applied)
- Disable feature flags
- Notify stakeholders
- Time estimate for rollback: _e.g., 15 minutes_

---

## 👥 Stakeholders & Notifications

- **Dev Contact:** @dev-username
- **QA Contact:** @qa-username
- **Product Owner:** @product-owner
- **Slack Channel Notification:** #prod-deploys

---

## 🕐 Deployment Window

- **Scheduled Date & Time:** YYYY-MM-DD @ HH:MM (UTC)
- **Approved by:** @approver

---

## ✅ Post-Deployment Validation

- [ ] Application accessible and functioning
- [ ] KPIs and dashboards show normal behavior
- [ ] Alerts and logs reviewed
- [ ] Confirmation sent to stakeholders