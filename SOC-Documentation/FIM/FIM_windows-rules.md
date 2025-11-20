## Windows Security Monitoring Rules for OSSEC/Wazuh

This document outlines a comprehensive set of security monitoring rules for Windows environments, specifically designed for use with OSSEC/Wazuh.
It aims to provide advanced threat detection capabilities while minimizing false positives through intelligent noise reduction.

```<!-- Windows Security Rules -->

<group name="syscheck,fim,windows">

  <!-- WINDOWS DEFENDER / ANTIVIRUS RULES -->
  
  <!-- Event ID 1116 - Malware Detection -->
  <rule id="800050" level="12">
    <if_sid>62100</if_sid>
    <field name="win.system.eventID">^1116$</field>
    <description>Windows Defender: Malware detected - HIGH PRIORITY - $(win.eventdata.threatName)</description>
    <options>no_full_log</options>
    <group>antivirus,malware,pci_dss_5.1,pci_dss_5.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.3,</group>
  </rule>

  <!-- Event ID 1117 - Threat Blocked -->
  <rule id="800051" level="10">
    <if_sid>62100</if_sid>
    <field name="win.system.eventID">^1117$</field>
    <description>Windows Defender: Threat blocked - $(win.eventdata.threatName)</description>
    <options>no_full_log</options>
    <group>antivirus,threat_blocked,pci_dss_5.1,pci_dss_5.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.3,</group>
  </rule>

  <!-- Windows Defender - Scan completed (informational only) -->
  <rule id="800054" level="2">
    <if_sid>62100</if_sid>
    <field name="win.system.eventID">^1001$</field>
    <options>no_full_log</options>
    <description>Windows Defender scan completed</description>
    <group>antivirus,scan_complete,</group>
  </rule>

  <!-- Windows Defender - Real-time protection disabled -->
  <rule id="800055" level="8">
    <if_sid>60005</if_sid>
    <field name="win.system.providerName">Microsoft-Windows-Windows Defender</field>
    <field name="win.system.eventID">^5001$</field>
    <description>Windows Defender real-time protection disabled</description>
    <group>antivirus,protection_disabled,</group>
  </rule>

  <!-- AUTHENTICATION RULES -->
  
  <!-- Failed Login Attempts - Noise Reduced -->
  <rule id="800060" level="0">
    <if_sid>60122</if_sid>
    <description>Windows logon failure - baseline</description>
    <group>authentication_failed,</group>
  </rule>

  <!-- Alert on multiple failed logins from same source -->
  <rule id="800063" level="10" frequency="5" timeframe="300">
    <if_matched_sid>800060</if_matched_sid>
    <same_source_ip />
    <description>Multiple failed login attempts from same source IP (Brute force attack)</description>
    <group>authentication_failed,brute_force,</group>
  </rule>

  <!-- Alert on account lockouts -->
  <rule id="800066" level="9">
    <if_sid>800060</if_sid>
    <field name="win.eventdata.subStatus">0xc0000234</field>
    <description>Account locked due to failed login attempts</description>
    <group>authentication_failed,account_lockout,</group>
  </rule>

  <!-- Alert on disabled account login attempts -->
  <rule id="800067" level="7">
    <if_sid>800060</if_sid>
    <field name="win.eventdata.subStatus">0xc0000072</field>
    <description>Login attempt to disabled account</description>
    <group>authentication_failed,disabled_account,</group>
  </rule>

  <!-- PRIVILEGE ESCALATION RULES -->
  
  <!-- Privilege Escalation - Noise Reduced -->
  <rule id="800070" level="0">
    <if_sid>60137</if_sid>
    <description>Privilege assignment detected - baseline</description>
    <group>privilege_escalation,</group>
    <options>no_full_log</options>
  </rule>

  <!-- SERVICE INSTALLATION RULES -->
  
  <!-- Service Installation - Noise Reduced -->
  <rule id="800080" level="0">
    <if_sid>60009</if_sid>
    <field name="win.system.eventID">^7045$</field>
    <description>New service installed - baseline</description>
    <group>service_installation,</group>
    <options>no_full_log</options>
  </rule>

  <!-- Whitelist services installed from Program Files -->
  <rule id="800082" level="0">
    <if_sid>800080</if_sid>
    <field name="win.eventdata.imageFileName" type="pcre2">(?i)^c:\\\\program files</field>
    <description>Service installed from Program Files - whitelisted</description>
    <group>service_installation,program_files,whitelist,</group>
  </rule>

  <!-- WMI & PERSISTENCE RULES -->
  
  <!-- WMI Event Subscription -->
  <rule id="800090" level="8">
    <if_sid>60000</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-WMI-Activity$</field>
    <field name="win.system.eventID">^5861$</field>
    <description>WMI event subscription created - possible persistence</description>
    <group>wmi,persistence,</group>
  </rule>

  <!-- SCHEDULED TASK RULES -->
  
  <!-- Base rule for all scheduled task creation -->
  <rule id="800100" level="3">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">Microsoft-Windows-TaskScheduler</field>
    <field name="win.system.eventID">^106$</field>
    <description>Scheduled task created (informational)</description>
    <group>scheduled_task,informational</group>
  </rule>

  <!-- Rule for Microsoft/Windows built-in tasks (low noise) -->
  <rule id="800101" level="2">
    <if_sid>800100</if_sid>
    <field name="win.eventdata.taskName" type="pcre2">^\\Microsoft\\|^\\Windows\\</field>
    <description>Microsoft/Windows built-in scheduled task created</description>
    <group>scheduled_task,system_task</group>
  </rule>

  <!-- Rule for system account tasks (low noise) -->
  <rule id="800102" level="2">
    <if_sid>800100</if_sid>
    <field name="win.eventdata.userContext" type="pcre2">^SYSTEM$|^NT AUTHORITY\\|^LOCAL SERVICE$|^NETWORK SERVICE$</field>
    <description>System account scheduled task created</description>
    <group>scheduled_task,system_account</group>
  </rule>

  <!-- Rule for tasks in system directories (low noise) -->
  <rule id="800103" level="4">
    <if_sid>800100</if_sid>
    <field name="win.eventdata.taskContent" type="pcre2">C:\\\\Windows\\\\System32|C:\\\\Program Files</field>
    <description>Scheduled task created in system directory</description>
    <group>scheduled_task,system_directory</group>
  </rule>

  <!-- Rule for suspicious user-created tasks (high priority) -->
  <rule id="800104" level="8">
    <if_sid>800100</if_sid>
    <field name="win.eventdata.taskName" type="pcre2" negate="yes">^\\Microsoft\\|^\\Windows\\</field>
    <field name="win.eventdata.userContext" type="pcre2" negate="yes">^SYSTEM$|^NT AUTHORITY\\|^LOCAL SERVICE$|^NETWORK SERVICE$</field>
    <description>Suspicious user-created scheduled task</description>
    <group>scheduled_task,suspicious_activity</group>
  </rule>

  <!-- DNS MONITORING RULES -->
  
  <!-- Base rule for all DNS queries (very low level) -->
  <rule id="800110" level="1">
    <if_sid>60000</if_sid>
    <field name="win.system.channel">^Microsoft-Windows-DNS-Client/Operational$</field>
    <field name="win.system.eventID">^3008$|^3020$</field>
    <description>DNS query performed (informational)</description>
    <group>dns,informational</group>
    <options>no_full_log</options>
  </rule>

  <!-- Rule for legitimate domains (no alert) -->
  <rule id="800111" level="1">
    <if_sid>800110</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">\.microsoft\.com$|\.windows\.com$|\.office\.com$|\.google\.com$|\.amazon\.com$|\.cloudflare\.com$</field>
    <description>DNS query to legitimate domain</description>
    <group>dns,legitimate</group>
  </rule>

  <!-- Rule for internal/local DNS queries -->
  <rule id="800112" level="1">
    <if_sid>800110</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">\.local$|\.internal$|\.corp$|^[^.]+$</field>
    <description>Internal DNS query</description>
    <group>dns,internal</group>
  </rule>

  <!-- Rule for suspicious domains -->
  <rule id="800113" level="6">
    <if_sid>800110</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">\.tk$|\.ml$|\.ga$|\.cf$|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}</field>
    <description>DNS query to suspicious domain or IP</description>
    <group>dns,suspicious</group>
  </rule>

  <!-- Rule for DGA-like domains -->
  <rule id="800114" level="8">
    <if_sid>800110</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">[a-z0-9]{15,}\.com$|[a-z0-9]{20,}\.</field>
    <description>DNS query to potential DGA domain</description>
    <group>dns,dga,malware</group>
  </rule>

  <!-- Rule for DNS tunneling indicators -->
  <rule id="800115" level="9">
    <if_sid>800110</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">[a-zA-Z0-9+/=]{50,}\.|TXT.*[a-zA-Z0-9+/=]{30,}</field>
    <description>Potential DNS tunneling detected</description>
    <group>dns,tunneling,exfiltration</group>
  </rule>

  <!-- FIREWALL RULES -->
  
  <!-- Base rule for all firewall rule additions -->
  <rule id="800120" level="3">
    <if_sid>60009</if_sid>
    <field name="win.system.channel">^Microsoft-Windows-Windows Firewall With Advanced Security/Firewall$</field>
    <field name="win.system.eventID">^2004$</field>
    <description>Windows Firewall rule added (informational)</description>
    <group>firewall,informational</group>
    <options>no_full_log</options>
  </rule>

  <!-- Rule for system/service account changes (low noise) -->
  <rule id="800121" level="2">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.modifyingUser" type="pcre2">^SYSTEM$|^NT AUTHORITY\\|^LOCAL SERVICE$|^NETWORK SERVICE$</field>
    <description>Firewall rule added by system account</description>
    <group>firewall,system_account</group>
  </rule>

  <!-- Rule for Windows Update/Defender changes -->
  <rule id="800122" level="2">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.ruleName">Windows Update|Windows Defender|Microsoft|@FirewallAPI</field>
    <description>Firewall rule added by Windows system component</description>
    <group>firewall,windows_component</group>
  </rule>

  <!-- Rule for application installer changes -->
  <rule id="800123" level="3">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.modifyingApplication">msiexec\.exe|setup\.exe|install\.exe</field>
    <description>Firewall rule added by application installer</description>
    <group>firewall,installer</group>
  </rule>

  <!-- Rule for administrative user changes (medium priority) -->
  <rule id="800124" level="5">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.modifyingUser" type="pcre2" negate="yes">^SYSTEM$|^NT AUTHORITY\\|^LOCAL SERVICE$|^NETWORK SERVICE$</field>
    <field name="win.eventdata.ruleName" negate="yes">Windows Update|Windows Defender|Microsoft|@FirewallAPI</field>
    <description>Firewall rule added by user account</description>
    <group>firewall,user_modification</group>
  </rule>

  <!-- Rule for suspicious firewall changes (high priority) -->
  <rule id="800125" level="8">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.action">Allow</field>
    <field name="win.eventdata.direction">Inbound</field>
    <field name="win.eventdata.protocol">TCP|UDP</field>
    <field name="win.eventdata.modifyingUser" type="pcre2" negate="yes">^SYSTEM$|^NT AUTHORITY\\</field>
    <description>Suspicious inbound firewall rule added by user</description>
    <group>firewall,suspicious,inbound_allow</group>
  </rule>

  <!-- Rule for potential backdoor creation -->
  <rule id="800126" level="10">
    <if_sid>800120</if_sid>
    <field name="win.eventdata.action">Allow</field>
    <field name="win.eventdata.direction">Inbound</field>
    <field name="win.eventdata.localPorts">3389|4444|5555|8080|9999</field>
    <description>High-risk inbound firewall rule added for common backdoor ports</description>
    <group>firewall,backdoor,high_risk</group>
  </rule>

  <!-- USB DEVICE MONITORING -->
  
  <!-- USB Device Connection -->
  <rule id="800130" level="4">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">Microsoft-Windows-Kernel-PnP</field>
    <field name="win.system.eventID">^400$</field>
    <description>USB device connected</description>
    <group>usb,device,</group>
  </rule>

  <!-- FILE INTEGRITY MONITORING (FIM) RULES -->
  <!-- SYSTEM32 DIRECTORY MONITORING -->
  
     <!-- Base rule for all System32 file changes - NOW CATCHES DIRECTLY -->
    <rule id="800200" level="4">
      <if_sid>550</if_sid> 
      <field name="file">c:\\windows\\system32\\</field>
      <description>File modified in System32 directory</description>
      <group>fim,system32,</group>
    </rule>

  <!-- Rule for legitimate system processes (low noise) -->
  <rule id="800202" level="2">
    <if_sid>800200</if_sid>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)svchost\.exe|winlogon\.exe|csrss\.exe|lsass\.exe|services\.exe|wininit\.exe</field>
    <description>System32 file modified by legitimate system process</description>
    <group>fim,system32,system_process</group>
  </rule>

  <!-- Rule for Windows Update/Installer changes -->
  <rule id="800203" level="3">
    <if_sid>800200</if_sid>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)msiexec\.exe|wuauclt\.exe|TiWorker\.exe|TrustedInstaller\.exe</field>
    <description>System32 file modified by Windows Update/Installer</description>
    <group>fim,system32,windows_update</group>
  </rule>

  <!-- Rule for temporary/cache files (very low priority) -->
  <rule id="800204" level="1">
    <if_sid>800200</if_sid>
    <field name="file" type="pcre2">(?i)\.tmp$|\.log$|\.cache$|\\catroot|\\wbem\\Logs|\\LogFiles</field>
    <description>Temporary/log file modified in System32</description>
    <group>fim,system32,temporary</group>
  </rule>

  <!-- Rule for driver/DLL changes by system -->
  <rule id="800205" level="5">
    <if_sid>800200</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.dll$|\.sys$|\.exe$</field>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)svchost\.exe|TrustedInstaller\.exe|msiexec\.exe</field>
    <description>System binary modified by trusted process</description>
    <group>fim,system32,binary_change</group>
  </rule>

  <!-- Rule for critical executable changes by non-system processes -->
  <rule id="800206" level="10">
    <if_sid>800200</if_sid>
    <field name="file" type="pcre2">(?i)\.exe$|\.dll$|\.sys$</field>
    <field name="syscheck.audit.process.name" type="pcre2" negate="yes">(?i)svchost\.exe|TrustedInstaller\.exe|msiexec\.exe|wuauclt\.exe|TiWorker\.exe</field>
    <description>Critical system binary modified by non-trusted process</description>
    <group>fim,system32,suspicious_binary</group>
  </rule>

  <!-- Rule for highly critical system files -->
  <rule id="800207" level="12">
    <if_sid>800200</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)ntoskrnl\.exe|hal\.dll|ntdll\.dll|kernel32\.dll|advapi32\.dll|user32\.dll</field>
    <field name="syscheck.audit.process.name" type="pcre2" negate="yes">(?i)TrustedInstaller\.exe|msiexec\.exe</field>
    <description>Highly critical system file modified by unauthorized process</description>
    <group>fim,system32,critical_core</group>
  </rule>

  <!-- Rule for potential malware injection -->
  <rule id="800208" level="15">
    <if_sid>800200</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.exe$|\.dll$</field>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)powershell\.exe|cmd\.exe|rundll32\.exe|regsvr32\.exe</field>
    <description>System32 binary modified by potentially malicious process</description>
    <group>fim,system32,malware_injection</group>
  </rule>

  <!-- FILE INTEGRITY MONITORING (FIM) RULES -->
  <!-- STARTUP DIRECTORY MONITORING -->
  
  <!-- Base rule for all startup directory changes - NOW CATCHES DIRECTLY -->
  <rule id="800209" level="4">
    <if_sid>550</if_sid>
    <field name="file">(?i)\\Startup\\</field>
    <description>File changed in startup directory: $file</description>
    <group>fim,startup</group>
  </rule>

  <!-- Rule for system account changes (low noise) -->
  <rule id="800210" level="2">
    <if_sid>800209</if_sid>
    <field name="syscheck.audit.process.euid" type="pcre2">(?i)SYSTEM|NT AUTHORITY\\SYSTEM</field>
    <description>Startup directory modified by system account</description>
    <group>fim,startup,system_account</group>
  </rule>

  <!-- Rule for installer processes (low noise) -->
  <rule id="800211" level="3">
    <if_sid>800209</if_sid>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)msiexec\.exe|setup\.exe|install\.exe|unins000\.exe|InstallShield</field>
    <description>Startup directory modified by installer process</description>
    <group>fim,startup,installer</group>
  </rule>

  <!-- Rule for legitimate shortcuts/links -->
  <rule id="800212" level="3">
    <if_sid>800209</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.lnk$|\.url$</field>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)explorer\.exe|rundll32\.exe</field>
    <description>Startup shortcut created by legitimate process</description>
    <group>fim,startup,shortcut</group>
  </rule>

  <!-- Rule for temporary files (very low priority) -->
  <rule id="800213" level="1">
    <if_sid>800209</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.tmp$|~\$|\.bak$</field>
    <description>Temporary file in startup directory</description>
    <group>fim,startup,temporary</group>
  </rule>

  <!-- Rule for user-initiated changes (medium priority) -->
  <rule id="800214" level="6">
    <if_sid>800209</if_sid>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)explorer\.exe</field>
    <field name="syscheck.path" type="pcre2" negate="yes">(?i)\.tmp$|~\$|\.bak$</field>
    <description>User modified startup directory via Explorer</description>
    <group>fim,startup,user_modification</group>
  </rule>

  <!-- Rule for executable files added (high priority) -->
  <rule id="800215" level="9">
    <if_sid>800209</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.exe$|\.bat$|\.cmd$|\.scr$|\.com$|\.pif$</field>
    <field name="syscheck.audit.process.name" type="pcre2" negate="yes">(?i)msiexec\.exe|setup\.exe|install\.exe</field>
    <description>Executable file added to startup directory</description>
    <group>fim,startup,persistence,executable</group>
  </rule>

  <!-- Rule for script files (high priority) -->
  <rule id="800216" level="8">
    <if_sid>800209</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.ps1$|\.vbs$|\.js$|\.wsf$|\.hta$</field>
    <description>Script file added to startup directory</description>
    <group>fim,startup,persistence,script</group>
  </rule>

  <!-- Rule for suspicious processes modifying startup -->
  <rule id="800217" level="12">
    <if_sid>800209</if_sid>
    <field name="syscheck.audit.process.name" type="pcre2">(?i)powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe</field>
    <field name="syscheck.path" type="pcre2" negate="yes">(?i)\.tmp$|\.log$</field>
    <description>CRITICAL: Suspicious process modified startup - Process: $(syscheck.audit.process.name) - File: $(syscheck.path)</description>
    <group>fim,startup,persistence,suspicious</group>
  </rule>

  <!-- Rule for unsigned executables in startup -->
  <rule id="800218" level="10">
    <if_sid>800209</if_sid>
    <field name="syscheck.path" type="pcre2">(?i)\.exe$</field>
    <field name="syscheck.audit.process.name" type="pcre2" negate="yes">(?i)msiexec\.exe|TrustedInstaller\.exe</field>
    <description>ALERT: Potentially unsigned executable in startup - $(syscheck.path)</description>
    <group>fim,startup,persistence,unsigned</group>
  </rule>

</group>    
```