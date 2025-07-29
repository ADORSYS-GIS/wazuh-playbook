# Windows Defender Agent Configuration

## OS Filter Syntax for Windows Defender Monitoring

When configuring Windows Defender monitoring in your agent configuration file (`agent.conf`), it's important to use the correct OS filter syntax.

### The Issue

The regex pattern `os="^Windows"` does not work for filtering Windows agents in the agent configuration. This is not a bug in Wazuh, but rather a configuration filter issue related to how the OS string is returned by the system.

### Root Cause

The OS string returned by the `getuname()` function (located in `file_op.c` at line 1579) causes the mismatch. The actual OS string returned for Windows systems doesn't match the expected regex pattern.

### Correct Syntax

Use `os="Windows"` instead of `os="^Windows"` for proper Windows agent filtering.

### Configuration Examples

#### ❌ Incorrect Configuration

```xml
<agent_config os="^Windows">
  <localfile>
    <log_format>eventlog</log_format>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
  </localfile>
</agent_config>
```

#### ✅ Correct Configuration

```xml
<agent_config os="Windows">
  <localfile>
    <log_format>eventlog</log_format>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
  </localfile>
</agent_config>
```

### Summary

- **Use**: `os="Windows"`
- **Avoid**: `os="^Windows"`
- **Note**: This is a configuration filter behavior, not a Wazuh bug
- **Technical Detail**: The OS string from `getuname()` function doesn't match the regex pattern 