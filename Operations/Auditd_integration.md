# Wazuh Audit Log Integration Documentation

## Wazuh Manager Configuration (Agent.conf)
Objective: Configure Wazuh Manager to collect and process auditd logs from agents.

### 1.1. Configure Audit Log Collection
Edit the agent.conf template on the Wazuh Manager (/var/ossec/etc/shared/default/agent.conf):

```xml
<agent_config>
  <!-- Auditd Log Collection -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</agent_config>
```
#### Explanation:

- log_format="audit" ensures proper parsing of audit logs.

- location points to the default auditd log file.

### 1.2. Deploy Configuration to Agents
The manager pushes agent.conf to all enrolled agents automatically.

Alternatively, manually restart agents to apply changes:
```bash
/var/ossec/bin/wazuh-control restart
```
### 1.3. Verify Log Collection
Check the Wazuh Manager logs (/var/ossec/logs/alerts/alerts.json) for incoming audit events.


## Wazuh Audit Rules Syntax Guide
(Based on Wazuh Audit Keys Mapping)

This documentation explains how to structure auditd rules to align with Wazuh's predefined key mappings (e.g., audit-wazuh-w:write).

### 1. Understanding Wazuh Audit Keys
The file /var/ossec/etc/lists/audit-keys maps audit keys to human-readable actions:

|Audit Key  |Action	|Description |
|----------|-------|------------|
|audit-wazuh-w|write|File modifications/deletions|
|audit-wazuh-r|read	|File read operations|
|audit-wazuh-a|attribute |	Metadata changes (e.g., permissions)|
|audit-wazuh-x|execute | File executions |
|audit-wazuh-c|command |	Root command executions |

### 2. Audit Rule Syntax for Wazuh
#### 2.1. Basic Structure
All rules must include:

- `-k <key>`: Matches Wazuh’s `audit-keys` (e.g., `-k audit-wazuh-w`).

- `-p <permissions>`: Defines monitored operations (`r`ead, `w`rite, `x`ecute, `a`ttribute).

#### 2.2. Rule Examples
- File Monitoring

```bash
# File writes (-w = watch, -p w = write)
-w /etc/passwd -p w -k audit-wazuh-w

# Directory monitoring (recursive)
-w /home/ -p rwa -k audit-wazuh-r  # Monitors read/write/attribute changes

# File executions
-w /usr/bin/ -p x -k audit-wazuh-x
```
- System Call Monitoring

```bash
# Root commands (euid=0)
-a exit,always -F euid=0 -S execve -k audit-wazuh-c

# Suspicious process execution (any user)
-a exit,always -S execve -k audit-wazuh-x
```
- Attribute Changes

```bash
# Monitor permission/ownership changes
-w /etc/shadow -p a -k audit-wazuh-a
```

### Conclusion
**Yes, integrate `auditd`** — it adds critical real-time visibility that rootcheck lacks. However:  
- **Replace rootcheck** with **FIM + auditd** for a modern, real-time monitoring stack.  
- **Tune rules** to avoid alert fatigue (focus on high-risk events).  

#### Reference:
- [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html#configuration)