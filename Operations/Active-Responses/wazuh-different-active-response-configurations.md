# Wazuh Active Response: Alternatives to Rule Matching

This document outlines alternatives to rule ID matching for triggering active responses in Wazuh, enabling flexible automation based on various alert criteria.

## 1. Alert Severity Level

Trigger active responses based on the severity level of an alert using the `<level>` tag in `/var/ossec/etc/ossec.conf`.

- **Example**: Trigger firewall-drop for alerts with severity 7 or higher.
    
    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>firewall-drop</command>
      <location>local</location>
      <level>7</level>
      <timeout>600</timeout>
    </active-response>
    ```
    

## 2. Rule Group

Use the `<rules_group>` tag to trigger responses for alerts belonging to specific rule groups (e.g., sql_injection).

- **Example**: Trigger firewall-drop for sql_injection group alerts.
    
    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>firewall-drop</command>
      <location>local</location>
      <rules_group>sql_injection,</rules_group>
      <timeout>600</timeout>
    </active-response>
    ```
    
- **Note**: End group names with a comma to avoid partial matches.

## 3. Location-Based Triggers

Specify where the response executes using the `<location>` tag, indirectly controlling triggers by targeting agents or the server.

- **Options**: local, server, defined-agent (with `<agent_id>`), all.
- **Example**: Trigger host-deny on a specific agent.
    
    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>host-deny</command>
      <location>defined-agent</location>
      <agent_id>001</agent_id>
      <rules_id>31171</rules_id>
      <timeout>600</timeout>
    </active-response>
    ```
    

## 4. Combining Criteria

Combine `<level>`, `<rules_group>`, and `<rules_id>` for flexible triggers (conditions are accumulative).

- **Example**: Trigger firewall-drop for multiple criteria.
    
    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>firewall-drop</command>
      <location>local</location>
      <level>7</level>
      <rules_group>authentication_failed,sql_injection,</rules_group>
      <rules_id>5763,31171</rules_id>
      <timeout>600</timeout>
    </active-response>
    ```
    

## 5. Repeat Offenders

Sets timeouts in minutes for repeat offenders. This is a comma-separated list of increasing timeouts that can contain a maximum of 5 entries. This option must be configured directly in the **`ossec.conf`** file of the agent (currently not supported by agents running on Windows), even when using a manager/agent setup with a centralized configuration of other settings via **`agent.conf`**

- **Example**: Increase timeouts for rule 5763.
    
    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>firewall-drop</command>
      <location>local</location>
      <rules_id>5763</rules_id>
      <timeout>180</timeout>
      <repeated_offenders>300,600,1200</repeated_offenders>
    </active-response>
    ```
    

## Best Practices

- **Test Configurations**: Validate in a controlled environment to avoid vulnerabilities.
- **Monitor Logs**: Check `/var/ossec/logs/active-responses.log` for trigger verification.
- **Restart Manager**: Run `systemctl restart wazuh-manager` after configuration changes.
- **Debugging**: Use `/var/ossec/bin/ossec-logtest` to test rules and logs.


**References**
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html#repeated-offenders
