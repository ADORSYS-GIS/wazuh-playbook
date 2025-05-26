## 1. SOC Concept for Wazuh
#### Objective
Design a Security Operations Center (SOC) framework that leverages Wazuh as the central platform for real-time threat detection, incident response, and compliance management, enabling proactive security operations and rapid incident resolution. 

### SOC Core Components
**1. Monitoring & Detection:** 
- **Wazuh Capabilities:** Utilize Wazuh’s file integrity monitoring (FIM), log analysis, and vulnerability detection.

- **Real-Time Analysis:** Deploy Wazuh agents across endpoints and servers for continuous monitoring of system logs, processes, and network activity.

- **Threat Intelligence:** Integrate Wazuh with external feeds and custom rules (Yara for malware, Snort for network threats) to enhance detection accuracy.

- **Anomaly Detection:** Leverage Wazuh’s built-in module to identify deviations from baseline behavior.

**2. Incident Response:**
- **Integration:** Connect Wazuh with Slack for real-time notifications, Jira for incident tracking.

- **Automation:** Use Wazuh’s Active Response module to execute predefined scripts (e.g., restart agent).



**3. Threat Intelligence:**
- **Feedback Loop:** Update detection rules based on post-incident analysis and emerging threats.

- **Custom Rules:** Develop and maintain a repository of Yara rules for malware detection.

**4. Compliance & Audit:**
- **Standards:** Align Wazuh configurations with frameworks like ISO 27001.

- **Reporting:** Generate automated compliance reports.

## 2.SOC Workflow with Wazuh

**i.  Alert Generation:** Wazuh detects a security event (e.g., brute force, malware, agent disconnection).

**ii.  Incident Classification:** Define severity (Low, Medium, High, Critical) based on Wazuh rule levels (0–15).
Wazuh parses logs, maps them to rules, and assigns severity.
Custom rules can be created to tune alert sensitivity and reduce false positives.

**iii.  Automated Notification and ticket creation:** 
- Alerts sent to Slack with relevant logs.
- Critical alerts → A Jira ticket is automatically created for tracking. (Based of wazuh rule [classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html#rules-classification))


**iv.  Remediation:**

- **Manual:** Analysts use playbooks for in-depth investigation.

- **Auto-Remediation:** Wazuh Active Response executes predefined actions.

#### v. Post-Incident Review: 
SOC team documents findings and updates security policies.

<img src="/Operations/IMAGES/soc_overview.png">


## 3. Demo Use Cases
### Use Case 1: Agent Disconnection
**1. Trigger:** Agent disconnected for over an extended period of time.

**2. Why it matters:** No logs = No visibility = Risk.

**3. Response:**

- Wazuh sends alert.

- Slack notification + Jira ticket auto-created (critical alert).

- Analyst uses remediation playbook:

  - Check host status & agent service.

  - Restart or reinstall agent.

  - Document fix in Jira.

✅ **Outcome:** Monitoring is restored, incident is tracked.


### Use Case 2: Brute Force Attack
**2. Trigger:** Multiple failed SSH logins (e.g., 5 in 120 secs).

**2. Why it matters:** Possible brute force attack.

**3. Response:**

- Wazuh detects the pattern.

- Active Response blocks IP automatically.

- Slack notification sent.

- (Optional) Jira ticket for repeated attempts.

✅ **Outcome:** Attack is blocked instantly, no human delay.