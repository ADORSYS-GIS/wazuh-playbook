# Incident Response Playbook  

## 1. Overview  
**Playbook Name:** [Enter Playbook Name]   
**Related Framework(s):** [MITRE ATT&CK / CIS / NIST / Other]  
**Last Updated:** [YYYY-MM-DD]  

## 2. Scope  
- **Objective:** [Describe what the playbook aims to address.]  
- **Use Case:** [Define the specific scenario this playbook is used for.]  
- **Applicable Systems:** [List affected systems (e.g., Linux servers, Windows endpoints, Cloud, etc.).]  

## 3. Trigger Conditions  
| **Trigger Type** | **Description** | **Detection Source** |  
|-----------------|----------------|--------------------|  
| Alert | [Describe alert conditions] | [SIEM / Wazuh / IDS / EDR] |  
| Event | [Describe event-based trigger] | [Log Analysis / Threat Intelligence] |  
| Manual | [Describe human-triggered actions] | [SOC Analyst / IT Team] |  

## 4. Response Actions  
### **4.1. Initial Analysis**  
- [ ] Validate the alert against known false positives.  
- [ ] Identify impacted assets and users.  
- [ ] Retrieve logs and evidence.  

### **4.2. Containment**  
- [ ] Isolate affected systems (if required).  
- [ ] Disable compromised accounts.  
- [ ] Block malicious IPs or domains.  

### **4.3. Eradication & Recovery**  
- [ ] Remove malicious artifacts (malware, scripts, etc.).  
- [ ] Patch vulnerabilities.  
- [ ] Restore affected services from backups.  

### **4.4. Post-Incident Review**  
- [ ] Document lessons learned.  
- [ ] Update security rules and detection logic.  
- [ ] Conduct a team debriefing session.  

## 5. Escalation & Communication  
| **Escalation Level** | **Contact Person/Team** | **Communication Channel** |  
|---------------------|------------------|------------------|  
| Tier 1 (SOC) | [SOC Analyst] | [Email / Slack / Ticketing System] |  
| Tier 2 (Security Engineer) | [Security Engineer] | [Phone / On-Call] |  
| Tier 3 (Management) | [CISO / IT Manager] | [Incident Report] |  

## 6. References & Documentation  
- [MITRE ATT&CK Tactics & Techniques](https://attack.mitre.org/)  
- [Wazuh Rule Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules.html)  
- [CIS Controls](https://www.cisecurity.org/controls/)  


---

### Incident Report

**1.Summary:** Incident type, impact, actions taken.

**2.Adversary Tactics:** ATT&CK techniques used.

**3.Response Actions:** Steps taken by IR team.

**4.Root Cause & Fixes:** Key learnings and security improvements.

**5.Team & Roles:** List of involved personnel.