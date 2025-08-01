# Windows Defender Agent Configuration Issue

## Current Behavior

When users apply Windows Defender settings via `agent.conf` for centralized configuration management, the Defender logs are not collected on Windows agents. The configuration file is correctly delivered to the agent, but the Defender monitoring fails to activate, even though other agent configuration settings work properly.

## Why It's Not Working

The issue occurs because the OS filter in the agent configuration uses `os="^Windows"`, which doesn't match due to Wazuh's internal logic not using regex matching in this context. The regex anchor `^` fails because of how the `getuname()` function retrieves the OS string.

**Failing Configuration:**
```xml
<agent_config os="^Windows">
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

The `getuname()` function returns strings like "Microsoft Windows 11 Home" which won't match the `^Windows` pattern, but will match `Windows`.

## Feedback from Investigation

The investigation confirmed several key points:

- `agent.conf` is properly delivered via the Wazuh manager
- The configuration appears in `merged.mg` on the agent
- The same configuration works when applied directly in `ossec.conf`
- Other `agent.conf` settings (such as File Integrity Monitoring) work correctly
- The issue is consistent across Wazuh agent versions v4.12.0 and v4.11.0

## Source Code Insight

The root cause lies in the Wazuh codebase, specifically in the [`file_op.c#getuname()`](https://github.com/wazuh/wazuh/blob/main/src/shared/file_op.c#L1579) function. This function returns the full OS string (e.g., "Microsoft Windows 11 Home") rather than just "Windows".

When the agent configuration system processes the OS filter, it performs a simple string match rather than regex evaluation. Therefore, the regex pattern `^Windows` fails to match the actual OS string returned by `getuname()`.

## Solution

Use the correct OS filter syntax without regex anchors:

```xml
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

**Key Changes:**
- Remove the `^` anchor from the OS filter
- Use `os="Windows"` instead of `os="^Windows"`
- This ensures the configuration applies to all Windows agents regardless of the specific Windows version 