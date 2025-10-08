
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
<agent_config os="Windows">
  <syscheck>
    <file_limit>
      <enabled>no</enabled>
    </file_limit>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <registry_settings>
      <windows_arch>both</windows_arch>
    </registry_settings>

    <!-- Core System and Configuration Files -->
    <directories>C:\Windows\System32\drivers\etc</directories>
    <directories>C:\Windows\System32\win.ini,C:\Windows\System32\system.ini</directories>
    <directories>C:\Windows\System32\inetsrv\metabase.xml</directories>

    <!-- Boot and Integrity Configuration -->
    <directories>C:\boot.ini</directories>
    <directories>C:\Windows\System32\bootres.dll</directories>
    <directories>C:\Windows\System32\CodeIntegrity\bootcat.cache</directories>

    <!-- Policy and Task Scheduling -->
    <directories>C:\Windows\System32\GroupPolicy\Machine,C:\Windows\System32\GroupPolicy\User</directories>
    <directories>C:\Windows\System32\Tasks</directories>

    <!-- Startup Locations and PowerShell Profiles -->
    <directories>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories>C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories>C:\Users\*\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1</directories>
    <directories>C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1</directories>

    <!-- Key System Directories (More specific than the entire System32) -->
    <directories>C:\Windows\System32\drivers</directories>
    <directories>C:\Windows\SysWOW64</directories>
    <directories>C:\Windows\SysNative\config</directories>

    <!-- User Data Directories -->
    <directories>C:\Users\*\Desktop</directories>
    <directories>C:\Users\*\Documents</directories>

    <!-- Registry Monitoring for Persistence and Policies -->
    <registry_entry>HKEY_LOCAL_MACHINE\Software\Classes\htmlfile\shell\open\command</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System</registry_entry>

    <!-- Registry Monitoring for Windows Defender Exclusions -->
    <registry_entry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes</registry_entry>
    <registry_entry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions</registry_entry>

    <!-- Ignored directories and files to reduce noise -->
    <ignore>C:\Windows\System32\LogFiles</ignore>
    <ignore>C:\Windows\Prefetch</ignore>
    <ignore>C:\Windows\Temp</ignore>
    <ignore>C:\Windows\SoftwareDistribution\Download</ignore>
    <ignore type="sregex">\.(log|tmp|temp|wam|err|swp|lock)$</ignore>
  </syscheck>

  <!-- Log Collection Settings -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>System</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Application</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <query>Event/System[Level&lt;=3]</query>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>
  <localfile>
    <log_format>iis</log_format>
    <location>C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log</location>
  </localfile>
</agent_config>
```

---

### 1. File Integrity Monitoring (`<syscheck>`)

This section configures the FIM engine.
*   **Frequency:** `<frequency>300</frequency>` sets the FIM scan interval to 300 seconds (5 minutes).
*   **Architecture:** `<windows_arch>both</windows_arch>` ensures that both 32-bit and 64-bit registry hives are monitored on 64-bit systems.

#### 1.1. Monitored Files and Directories

The following table details the files and directories being monitored and the rationale for their inclusion.

| Path / File | Description |
| :--- | :--- |
| **Core System & Config** | |
| `C:\Windows\System32\drivers\etc` | Contains critical network configuration files, including `hosts`, `networks`, and `protocol`. Modifications can redirect traffic. |
| `...\win.ini`, `...\system.ini` | Legacy system configuration files that can still be used by malware for persistence. |
| `...\inetsrv\metabase.xml` | The core configuration file for Microsoft Internet Information Services (IIS). |
| **Boot and Integrity** | |
| `C:\boot.ini` | Legacy bootloader configuration file. Changes can prevent the system from booting or cause it to load malicious code. |
| `...\bootres.dll` | Contains resources used during the Windows boot process. |
| `...\CodeIntegrity\bootcat.cache` | A component of Secure Boot that helps ensure the integrity of boot-time drivers. |
| **Policy and Tasks** | |
| `...\GroupPolicy\` | Monitors local Group Policy Objects (GPOs). Changes can weaken system security settings. |
| `...\Tasks` | Contains definitions for Scheduled Tasks. Attackers frequently use tasks to establish persistence. |
| **Startup & PowerShell** | |
| `...\Start Menu\Programs\Startup` | Global and user-specific startup folders. Any program placed here will run at logon. |
| `...\PowerShell_profile.ps1` | PowerShell profile scripts that execute automatically when a PowerShell session starts. A common persistence vector. |
| **Key System Directories** | |
| `...\drivers` | Location for all system hardware drivers. Addition of a malicious driver can lead to a rootkit. |
| `C:\Windows\SysWOW64` | The 32-bit system directory on 64-bit Windows. Critical for system operation. |
| `...\SysNative\config` | Contains the core system registry hives (SAM, SECURITY, SYSTEM, SOFTWARE). |
| **User Data** | |
| `C:\Users\*\Desktop`, `...\Documents` | Monitors for unexpected file creation or modification in key user directories. Can be noisy but useful for detecting ransomware activity. |

#### 1.2. Monitored Registry Keys

The following registry keys and hives are monitored for changes.

| Registry Key | Description |
| :--- | :--- |
| **Persistence Mechanisms** | |
| `HKLM\...\Run`, `...\RunOnce` | The most common registry locations for malware to configure auto-start programs. |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Defines all system services. New or modified services are a primary method for achieving privileged persistence. |
| `HKLM\...\Classes\htmlfile\shell\open\command` | A registry key that can be hijacked to execute malicious code when an HTML file is opened. |
| **Policies & Security Settings** | |
| `HKLM\...\CurrentVersion\Policies` | Monitors for changes to system-wide security policies and restrictions. |
| `HKLM\...\Policies\System` | Contains critical security settings, including User Account Control (UAC) behavior. |
| **Antivirus Exclusions** | |
| `HKLM\...\Windows Defender\Exclusions\` | Monitors for new file paths, processes, or extensions being excluded from Windows Defender scans. Attackers add exclusions to evade detection. |

#### 1.3. FIM Exclusions (`<ignore>`)

To ensure stability and reduce alert fatigue, the following high-volume, low-risk locations and file types are excluded from FIM scans.

| Path / Regex | Rationale |
| :--- | :--- |
| `C:\Windows\System32\LogFiles` | Contains system and application log files that change constantly. |
| `C:\Windows\Prefetch` | Caching directory used by Windows to speed up application loading. Files here change frequently. |
| `C:\Windows\Temp` | A temporary directory for the system and applications. |
| `...\SoftwareDistribution\Download` | Directory where Windows Update downloads and stores temporary installation files. |
| `\.(log\|tmp\|temp\|...)$` | A regular expression to ignore common temporary and log file extensions across all monitored directories. |

---

### 2. Log Collection (`<localfile>`)

This section configures the Wazuh agent to actively collect and forward logs from critical Windows Event Channels and specific application log files.

| Type | Location | Value / Purpose |
| :--- | :--- | :--- |
| Event Channel | `Security` | The most critical log for security. Contains logon/logoff events, privilege use, object access, and other security audit data. |
| Event Channel | `System` | Contains events related to the operating system itself, such as driver failures, service start/stop events, and system errors. |
| Event Channel | `Application` | Records events logged by applications running on the system. |
| Event Channel | `Microsoft-Windows-PowerShell/Operational` | Essential for modern threat detection. Captures PowerShell command history and script block execution, even in fileless attacks. |
| Event Channel | `Microsoft-Windows-TaskScheduler/Operational` | Provides detailed logs on the creation, modification, and execution of Scheduled Tasks. |
| Event Channel | `Microsoft-Windows-Sysmon/Operational` | Collects highly detailed logs from Sysmon (if installed), including process creation, network connections, and file hashes. |
| File | `C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log` | Collects web server access logs from Microsoft IIS, crucial for monitoring web-based attacks. |