# Wazuh Audit Log Integration Documentation

## Part 1: Wazuh Manager Configuration (Agent.conf)

### 1.1. Configure Audit Log Collection
Edit the agent.conf template on the Wazuh Manager (/var/ossec/etc/shared/agent.conf):

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

## Part 2: Group-Based Configuration via Wazuh Dashboard
### 2.1. Assign Agents to Groups
1. Navigate to: **Management → Groups**

2. Create a group (e.g., `audit`) and assign relevant agents.

### 2.2. Apply Group-Specific Audit Config
1. Go to: **Management → Configuration → Groups**

2. Select your group (`audit`) and edit agent.conf:

```xml
<agent_config>
<!-- Linux agents -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
<!-- MacOS linux -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/system.log</location>
  </localfile>

<!-- Windows Agents -->
  <localfile>
    <log_format>eventlog</log_format>
    <location>Security</location>
  </localfile>
</agent_config>
```
3. **Save** – Changes deploy automatically to group members.

**Advantages:**

- No manual file edits required.
- Changes are version-controlled and reversible.



#### Alternatively, manually restart agents to apply changes:
```bash
/var/ossec/bin/wazuh-control restart
```
**Verify Log Collection:**
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
### Link to audit rules from the SCA module:
- [Ensure changes to system administration scope (sudoers) is collected](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28597.md)
-  [Ensure actions as another user are always logged.](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28598.md)
- [Ensure events that modify date and time information are collected](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28599.md)
- [Ensure events that modify the system's network environment](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28600.md)
- [Ensure events that modify user/group information are collected.](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28601.md)
- [Ensure session initiation information is collected.](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28602.md)
- [Ensure login and logout events are collected.](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28603.md)
- [Ensure events that modify the system's Mandatory Access Control](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28604.md)
- [Ensure the audit configuration is immutable.](/Configuration%20Assesment/CIS%20Ubuntu%20Linux%2022.04%20LTS%20Benchmark%20v1.0.0./28605.md)
#### Reference:
- [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html#configuration)