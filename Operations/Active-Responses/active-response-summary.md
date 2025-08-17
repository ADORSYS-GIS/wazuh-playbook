# Phase 4: Active Responses

**Introduction**

Wazuh is an open-source Security Information and Event Management (SIEM) platform used in Security Operations Centers (SOCs) to monitor systems and respond to security threats. The Active Response feature automates immediate actions when threats are detected, such as blocking a malicious IP address or quarantining a harmful file. This guide explains Active Responses, how to configure them, write custom scripts, and test them, designed for readers with little to no security background. It includes a visual diagram to show where actions occur and references official Wazuh documentation for further exploration.

### Why Active Responses Matter

- **Speed**: Instantly mitigates threats, reducing potential damage.
- **Consistency**: Ensures uniform responses across all monitored systems.
- **Efficiency**: Automates repetitive tasks, freeing security teams for complex investigations.

### Key Components

- **Endpoint (Agent)**: A monitored device (e.g., server, laptop) that detects security events.
- **Wazuh Server (Manager)**: The central system that analyzes events and triggers responses.
- **Active Response Scripts**: Programs that execute automated actions, either built-in or custom.

## What Are Active Responses?

Active Responses in Wazuh are automated actions triggered by specific security alerts to neutralize threats in real-time. When Wazuh detects suspicious activity, like a hacker attempting multiple logins (SSH brute-force) or malware on a system, Active Responses can block the attacker’s IP, quarantine the file, or send an alert to tools like Slack. These responses reduce the need for manual intervention, making security management faster and more reliable. They are configured to run on either the Wazuh server or the affected endpoint, depending on the setup.

### Use Cases

- **SSH Brute-Force (Rule 5710)**: Blocks an IP address after repeated failed login attempts.
- **Malware Detection**: Quarantines a malicious file detected by a YARA scan.
- **High-Severity Alerts**: Sends notifications to Slack for critical events (e.g., level 12+ alerts).

### Benefits

- **Proactive Defense**: Stops threats before they escalate.
- **Customizable**: Allows tailored responses via scripts.
- **Scalable**: Works across multiple endpoints in a network.

## Types of Active Responses

Active Responses are divided into two types based on reversibility:

| **Type** | **Description** | **Example** | **Command Handling** |
| --- | --- | --- | --- |
| **Stateless** | One-time actions that cannot be undone. | Sending a Slack notification. | Only handles "add". |
| **Stateful** | Actions that can be reversed after a timeout. | Blocking/unblocking an IP. | Handles "add" and "delete". |
- **Stateless**: Executes a single action (e.g., sending an alert) without a mechanism to undo it.
- **Stateful**: Performs an action (e.g., block an IP) and reverses it after a set time (e.g., unblock after 600 seconds).

## Configuring Active Responses

Active Responses are set up in the Wazuh manager’s configuration file (`/var/ossec/etc/ossec.conf`) and require scripts to be deployed in specific directories.

### Step 1: Define the Command

Add a <command> block to specify the script:

```xml
<command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
</command>
```

- `<name>`: Unique command name (e.g., host-deny).
- `<executable>`: Script file in /var/ossec/active-response/bin (Linux).
- `<timeout_allowed>`: Set to yes for stateful responses.

### Step 2: Configure the Active Response

Add an <active-response> block to define trigger conditions:

```xml
<active-response>
    <disabled>no</disabled>
    <command>host-deny</command>
    <location>local</location>
    <rules_id>5710</rules_id>
    <timeout>600</timeout>
</active-response>
```

- <disabled>: Set to no to enable.
- <command>: Matches the <name> from the command block.
- <location>: Where the script runs:
    - local: On the agent where the event occurred.
    - server: On the Wazuh manager.
    - defined-agent: On a specific agent (requires <agent_id>).
    - all: On all agents (use sparingly).
- <rules_id>: Rule ID to trigger the response (e.g., 5710 for SSH brute-force).
- <timeout>: Time (seconds) before the "delete" action for stateful responses.

### Step 3: Deploy Scripts

Place scripts in the correct directory:

- **Linux/Unix**: /var/ossec/active-response/bin
- **macOS**: /Library/Ossec/active-response/bin
- **Windows**: C:\Program Files (x86)\ossec-agent\active-response\bin

Set permissions (Linux example):

```bash
sudo chmod 750 /var/ossec/active-response/bin/host-deny
sudo chown root:wazuh /var/ossec/active-response/bin/host-deny
```

For Windows, convert Python scripts to .exe using pyinstaller or use a launcher.cmd wrapper.

### Step 4: Restart Wazuh Manager

Apply changes:

```bash
sudo systemctl restart wazuh-manager
```

### Step 5: Test the Configuration

- Simulate an SSH brute-force attack in the test environment.
- Check logs in `/var/ossec/logs/active-responses.log`.
- Use dry-run mode to test scripts safely.
- Filter internal IPs to prevent accidental blocking of legitimate traffic.

## Writing Custom Scripts

Custom scripts let you decide what Wazuh does when it finds a threat, like blocking an IP or sending an alert. They read a message (in JSON format) from Wazuh and act based on whether it says “add” or “delete”

Custom scripts should be placed in the appropriate directory based on the operating system:

- Linux/Unix: `/var/ossec/active-response/bin` (create the script here, e.g., `custom-ar.py`).
- macOS: `/Library/Ossec/active-response/bin` (create the script here).
- Windows: `C:\Program Files (x86)\ossec-agent\active-response\bin` (create the script here, potentially as .exe for Python).

### Key Considerations

- **Input Handling**: Scripts read JSON from STDIN with alert details (e.g., rule ID, source IP) and the command field.
    - Example JSON:
        
        ```json
        {
            "version": 1,
            "origin": {"name": "", "module": ""},
            "command": "add",
            "parameters": {"alert": {"rule": {"id": "5710"}, "srcip": "192.168.1.100"}}
        }
        ```
        
- **Stateless Scripts**:
    - Check for "add" command.
    - Perform a one-time action (e.g., send a Slack notification).
- **Stateful Scripts**:
    - Check the command:
        - **"add"**: Executes the main action (e.g., block an IP). Triggered when the alert is detected.
        - **"delete"**: Reverts the action (e.g., unblock the IP). Triggered after the <timeout> period in the configuration.
    - Build a JSON control message to confirm execution.
    - Handle responses ("continue" or "abort") from Wazuh.
- **Error Handling**:
    - Read STDIN up to a newline (\n) to avoid deadlocks.
    - Log actions to `/var/ossec/logs/active-responses.log` for debugging.

### When to Use "add" or "delete"

- **"add"**: Initiates the action when the alert triggers (e.g., block an IP for rule 5710).
- **"delete"**: Reverses the action after the timeout period (e.g., unblock the IP after 600 seconds). The <timeout> in `ossec.conf` determines when "delete" is sent.

### Example Custom Script (Python)

This script creates a file for an "add" command and removes it for a "delete" command:

```python
import json
import sys
import os
import logging

# Configure logging to Wazuh's log directory
logging.basicConfig(
    filename='/var/ossec/logs/active-responses.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def process_active_response():
    try:
        # Read JSON input from STDIN (sent by Wazuh)
        input_data = sys.stdin.read().strip()
        if not input_data:
            logging.error("No input data received from Wazuh")
            return

        # Parse JSON
        data = json.loads(input_data)
        command = data.get('command', 'unknown')
        parameters = data.get('parameters', {})
        alert = parameters.get('alert', {})
        rule_id = alert.get('rule', {}).get('id', 'unknown')
        src_ip = alert.get('srcip', 'unknown')

        # Log the received command and details
        logging.info(f"Received command: {command}, Rule ID: {rule_id}, Source IP: {src_ip}")

        # Handle the command
        if command == 'add':
            action = f"Blocked IP {src_ip} for rule {rule_id}"
            with open("/var/ossec/active-response/ar-test-result.txt", "w") as f:
                f.write(f"{action}\n")
            logging.info(action)

            # Send control message for stateful response
            control_msg = {
                "version": 1,
                "origin": {"name": "custom-ar", "module": "active-response"},
                "command": "check_keys",
                "parameters": {"keys": [rule_id]}
            }
            print(json.dumps(control_msg))
        elif command == 'delete':
            action = f"Unblocked IP {src_ip} for rule {rule_id}"
            result_file = "/var/ossec/active-response/ar-test-result.txt"
            if os.path.exists(result_file):
                os.remove(result_file)
                logging.info(action)
            else:
                logging.info(f"No action to undo for IP {src_ip}")
        else:
            logging.warning(f"Unknown command: {command}")

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    process_active_response()
```

### Configuring the Script

Add to ossec.conf:

```xml
<command>
    <name>custom-ar</name>
    <executable>custom-ar.py</executable>
    <timeout_allowed>yes</timeout_allowed>
</command>
<active-response>
    <disabled>no</disabled>
    <command>custom-ar</command>
    <location>local</location>
    <rules_id>5710</rules_id>
    <timeout>60</timeout>
</active-response>
```

**References**
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html#stateful-active-response

- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html


