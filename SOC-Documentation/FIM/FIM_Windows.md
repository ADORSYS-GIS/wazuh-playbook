
***

# Windows Endpoint Security Configuration Policy

### Overview

This document defines the standard agent configuration for the organization's Windows endpoints. The policy is designed to provide comprehensive security visibility through two main functions:

1.  **File Integrity Monitoring (FIM):** Detects and alerts on unauthorized modifications to critical system files, directories, and registry keys. This is a core defense against malware, unauthorized configuration changes, and security breaches.
2.  **Log Collection:** Gathers essential security, system, and application logs to provide context for investigations and threat hunting.

This configuration is optimized to monitor high-value targets while minimizing noise from routine system operations.

### Scope

This configuration applies to all designated Windows Desktop and Server systems enrolled in the corporate endpoint security management platform (Wazuh).

### Configuration Breakdown

The agent configuration is divided into two primary sections: `<syscheck>` for File Integrity Monitoring and `<localfile>` for log collection.

```xml
  <!-- Windows Endpoints configuration -->
  <agent_config os="Windows">
    <!-- File Integrity Monitoring (FIM) -->
    <syscheck>
      <disabled>no</disabled>
      <frequency>60</frequency>
      <!-- 12 hours -->
      <scan_on_start>yes</scan_on_start>
      <alert_new_files>yes</alert_new_files>
      <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
      <restart_audit>yes</restart_audit>
      <!-- Critical System Directories -->
      <directories>C:\Windows\System32,C:\Windows\SysWOW64</directories>
      <directories>C:\Windows\Boot</directories>
      <directories>C:\Windows\System32\drivers</directories>
      <!-- Program Files -->
      <directories>C:\Program Files,C:\Program Files (x86)</directories>
      <!-- Startup and Autorun Locations -->
      <directories>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
      <directories>C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
      <!-- High-Risk Temp Directories -->
      <directories>C:\Windows\Temp,C:\Users\*\AppData\Local\Temp,C:\Temp</directories>
      <!-- Critical Configuration Files -->
      <directories>C:\Windows\System32\drivers\etc\hosts,C:\bootmgr</directories>
      <!-- Web Server Directories (if applicable) -->
      <directories>C:\inetpub\wwwroot</directories>
      <!-- Security Software Directories -->
      <directories>C:\Program Files\Windows Defender,C:\Program Files (x86)\ossec-agent</directories>
      <!-- Specific Executable Monitoring -->
      <directories>C:\Windows\System32\cmd.exe,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</directories>
      <directories>C:\Windows\System32\svchost.exe,C:\Windows\System32\lsass.exe</directories>
      <!-- Registry Monitoring -->
      <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
      <windows_registry>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
      <windows_registry>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\NetworkProvider\Order</windows_registry>
      <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy</windows_registry>
      <!-- Files/directories to ignore -->
      <ignore>C:\Windows\System32\config</ignore>
      <ignore>\.(log|tmp|temp|swp|bak)$</ignore>
      <ignore>C:\Windows\SoftwareDistribution</ignore>
      <ignore>C:\Windows\WindowsUpdate.log</ignore>
      <ignore>C:\Windows\Prefetch</ignore>
      <ignore>C:\Windows\System32\wbem\Logs</ignore>
      <ignore>C:\Windows\System32\LogFiles</ignore>
      <ignore>C:\Windows\Logs</ignore>
      <ignore>\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files</ignore>
      <ignore>\\AppData\\Local\\Temp\\Low</ignore>
      <ignore>C:\Users\*\AppData\Local\Temp</ignore>
    </syscheck>
    <!-- Log Collection -->
    <localfile>
      <location>Security</location>
      <log_format>eventchannel</log_format>
      <query>Event/System[EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756]</query>
    </localfile>
    <localfile>
      <location>System</location>
      <log_format>eventchannel</log_format>
      <query>Event/System[EventID=7034 or EventID=7035 or EventID=7036 or EventID=7040 or EventID=6005 or EventID=6006 or EventID=6008 or EventID=6013]</query>
    </localfile>
    <localfile>
      <location>Application</location>
      <log_format>eventchannel</log_format>
      <query>Event/System[Level=1 or Level=2 or Level=3]</query>
    </localfile>
    <localfile>
      <location>Microsoft-Windows-PowerShell/Operational</location>
      <log_format>eventchannel</log_format>
      <query>Event/System[EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106]</query>
    </localfile>
    <localfile>
      <location>Microsoft-Windows-Windows Defender/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    <localfile>
      <log_format>json</log_format>
      <location>C:\Program Files\Suricata\log\eve.json</location>
    </localfile>
    <!-- Command Monitoring -->
    <localfile>
      <location>command</location>
      <command>powershell.exe -Command "Get-Process | Select-Object Name,Id,CPU,WorkingSet | ConvertTo-Json"</command>
      <alias>process_monitor</alias>
      <frequency>21600</frequency>
      <log_format>full_command</log_format>
    </localfile>
    <localfile>
      <location>command</location>
      <command>powershell.exe -Command "Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic'} | Select-Object Name,Status,StartType | ConvertTo-Json"</command>
      <alias>service_monitor</alias>
      <frequency>21600</frequency>
      <log_format>full_command</log_format>
    </localfile>
    <localfile>
      <location>command</location>
      <command>netstat -an</command>
      <alias>netstat</alias>
      <frequency>21600</frequency>
      <log_format>full_command</log_format>
    </localfile>
  </agent_config>

```

