# Implementation Documentation: Integration & Remediation

## 1. Introduction
This document provides a detailed explanation of the **Integration & Remediation** process in Wazuh, ensuring that team members understand the implementation, configuration, and workflow. It covers how alerts are processed, notifications are sent, and incidents are remediated both manually and automatically.

## 2. Integration
### **1. Notification System**
#### **Slack Integration**
- **Purpose:** Sends real-time alerts for security events to notify the team instantly.
- **Why?** Allows immediate awareness of security incidents, reducing response time.
- **Implementation:**
  - Configured via Webhooks in Wazuh (`/var/ossec/etc/ossec.conf`).
  - Alerts include details like affected agents, timestamp, and event severity.
  - Example: If an agent disconnects for over an extended period of time, a Slack alert is triggered in the `#security-alerts` channel.

  ```
  <integration>
        <name>slack</name>
        <hook_url>https://hooks.slack.com/services/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</hook_url> <!-- Replace with your Slack hook URL -->
        <!--<rule_id>504,506,5503,120100</rule_id>-->
        <level>3</level>
        <alert_format>json</alert_format>
        <event_location></event_location>
        <options>{"pretext": "Wazuh Alert"}</options> <!-- Replace with your custom JSON object -->
    </integration>
  ```

#### **Jira Integration**
- **Purpose:** Automates incident tracking by creating tickets for critical security alerts.
- **Why?** Provides structured tracking and assignment for security incidents.
- **Implementation:**
  - Integrated via API in Wazuh (`/var/ossec/integrations/custom-jira` and `/var/ossec/integrations/custom-jira.py`).
  - When an alert is generated, a Jira ticket is created with predefined fields and details.
  - Example: A ticket is automatically logged when an agent remains disconnected beyond the threshold.

  ```
  <integration>
        <name>custom-jira</name>
        <hook_url>https://api-private.atlassian.com/automation/webhooks/jira/a/b59302f3-a656-4cfa-8007-9c90e3d75343/0195b2a3-f082-768f-86c6-0f8210e7cea3</hook_url>
        <api_key>406175b550e5966eb2d5c03d791bcd7639aea915</api_key>
        <alert_format>json</alert_format>
        <level>10</level>
        <rule_id>120100</rule_id>
  </integration>
  ```

## 3. Remediation
### **1. Manual Remediation (Playbooks)**
- **Purpose:** Provides structured guidance for resolving security incidents manually.
- **Why?** Ensures consistency and thorough investigation of security issues.
- **Implementation:**
  - Playbooks are attached to Jira tickets detailing response steps.
  - Example: If an agent is offline, the playbook guides the analyst through checking logs, network status, and host integrity.

**Example Playbook for Agent Disconnection:**
1. Check Wazuh logs (`/var/ossec/logs/ossec.log`).
2. Verify agent connectivity (`/var/ossec/bin/agent_control -l`).
3. Restart the agent (`/var/ossec/bin/wazuh-control restart`).
4. If unresolved, reinstall the agent following the documentation.

### **2. Auto-Remediation (Active Response)**
- **Purpose:** Enables Wazuh to take immediate action against detected threats without human intervention.
- **Why?** Reduces response time for critical security threats.
- **Implementation:**
  - Configured in Wazuh’s **Active Response** module (`/var/ossec/active-response/bin/`).
  - Example: If a brute-force attack is detected, Wazuh disables the attacker’s user account automatically.

**Example Active Response Workflow for Brute-Force Attacks:**
1. Wazuh detects multiple failed SSH login attempts.
2. The system logs the event and generates an alert.
3. Active Response runs a predefined action to disable the suspicious user account.
4. A notification is sent to Slack and a Jira ticket is created.

## 4. Implementation Summary
| Feature | Purpose | Implementation | Example |
|---------|---------|---------------|---------|
| Slack Integration | Real-time alerts | Webhook in Wazuh | Notify when agent disconnects |
| Jira Integration | Incident tracking | API-based ticket creation | Log ticket for offline agent |
| Manual Remediation | Step-by-step recovery | Playbooks in Jira | Investigate disconnected agent |
| Auto-Remediation | Immediate threat response | Wazuh Active Response | Disable attacker’s user account |



## Secure Credential Management with AWS Secrets Manager and Kubernetes
To ensure sensitive credentials (e.g., Slack Webhooks, Jira API keys) are securely managed and not exposed in plaintext, we leverage AWS Secrets Manager in combination with Kubernetes Secrets.

### Why?
- Keeps credentials out of version control and Helm values files.

- Follows security best practices by centralizing and rotating secrets using AWS.

- Seamlessly integrates with Kubernetes deployments via Helm.

### Implementation Workflow:
1. Store credentials in AWS Secrets Manager, e.g.:

   `wazuh/slack-webhook`

   `wazuh/jira-api-key`


2. Create Kubernetes Secrets from these values

3. Reference the Kubernetes Secret in your Helm values.yaml
