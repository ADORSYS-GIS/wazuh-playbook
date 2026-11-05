# Wazuh Windows Security Monitoring Rules

This XML file contains Wazuh rules for monitoring Windows security events including malware detection, file integrity monitoring (FIM) in critical system locations, and startup persistence mechanisms.

```xml
<!-- ====================== WINDOWS DEFENDER MALWARE DETECTION ====================== -->
<group name="syscheck,fim,windows,">
  <!-- Event ID 1116 - Malware Detection -->
  <rule id="600050" level="12">
    <if_sid>62100</if_sid>
    <field name="win.system.eventID">^1116$</field>
    <description>Windows Defender: Malware detected - HIGH PRIORITY - $(win.eventdata.threatName)</description>
    <options>no_full_log</options>
    <group>antivirus,malware,pci_dss_5.1,pci_dss_5.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.3,</group>
  </rule>

  <!-- Event ID 1117 - Threat Blocked -->
  <rule id="600051" level="10">
    <if_sid>62100</if_sid>
    <field name="win.system.eventID">^1117$</field>
    <description>Windows Defender: Threat blocked - $(win.eventdata.threatName)</description>
    <options>no_full_log</options>
    <group>antivirus,threat_blocked,pci_dss_5.1,pci_dss_5.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.3,</group>
  </rule>

<!-- ====================== FIM - SYSTEM32 MONITORING ====================== -->
  <!-- Parent: Syscheck file change in System32 -->
  <rule id="600200" level="4">
    <if_sid>550</if_sid>
    <field name="file">C:\\Windows\\System32</field>
    <description>File modified in System32 directory</description>
    <group>fim,system32</group>
  </rule>

  <!-- Critical system binary modified by non-trusted process -->
  <rule id="600205" level="10">
    <if_sid>600200</if_sid>
    <field name="file">\.exe$|\.dll$|\.sys$</field>
    <field name="audit.process.name" negate="yes">svchost\.exe|TrustedInstaller\.exe|msiexec\.exe|wuauclt\.exe|TiWorker\.exe</field>
    <description>Critical system binary modified by non-trusted process</description>
    <group>fim,system32,suspicious_binary</group>
  </rule>

  <!-- Highly critical system file modified by unauthorized process -->
  <rule id="600206" level="12">
    <if_sid>600200</if_sid>
    <field name="file">ntoskrnl\.exe|hal\.dll|ntdll\.dll|kernel32\.dll|advapi32\.dll|user32\.dll</field>
    <field name="audit.process.name" negate="yes">TrustedInstaller\.exe|msiexec\.exe</field>
    <description>Highly critical system file modified by unauthorized process</description>
    <group>fim,system32,critical_core</group>
  </rule>

  <!-- System32 binary modified by potentially malicious process -->
  <rule id="600207" level="15">
    <if_sid>600200</if_sid>
    <field name="file">\.exe$|\.dll$</field>
    <field name="audit.process.name">powershell\.exe|cmd\.exe|rundll32\.exe|regsvr32\.exe</field>
    <description>System32 binary modified by potentially malicious process</description>
    <group>fim,system32,malware_injection</group>
  </rule>
</group>

<!-- ====================== FIM - STARTUP PERSISTENCE MONITORING ====================== -->
<group name="fim,startup,">
  <!-- Parent: Startup directory change -->
  <rule id="600208" level="4">
    <if_sid>550</if_sid>
    <field name="file">\\Startup\\</field>
    <description>File changed in startup directory: $(file)</description>
    <group>fim,startup,</group>
  </rule>

  <!-- Executable file added to startup directory -->
  <rule id="600214" level="9">
    <if_sid>600208</if_sid>
    <field name="file">\.exe$|\.bat$|\.cmd$|\.scr$|\.com$|\.pif$</field>
    <field name="audit.process.name" negate="yes">msiexec\.exe|setup\.exe|install\.exe</field>
    <description>Executable file added to startup directory</description>
    <group>fim,startup,persistence,executable</group>
  </rule>

  <!-- Script file added to startup directory -->
  <rule id="600215" level="8">
    <if_sid>600208</if_sid>
    <field name="file">\.ps1$|\.vbs$|\.js$|\.wsf$|\.hta$</field>
    <description>Script file added to startup directory</description>
    <group>fim,startup,persistence,script,</group>
  </rule>

  <!-- Suspicious process modified startup directory -->
  <rule id="600216" level="12">
    <if_sid>600208</if_sid>
    <field name="audit.process.name">powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe</field>
    <field name="file" negate="yes">\.tmp$|\.log$</field>
    <description>Suspicious process modified startup directory</description>
    <group>fim,startup,persistence,suspicious</group>
  </rule>

  <!-- Potentially unsigned executable added to startup -->
  <rule id="600217" level="10">
    <if_sid>600208</if_sid>
    <field name="file">\.exe$</field>
    <field name="audit.process.name" negate="yes">msiexec\.exe|TrustedInstaller\.exe</field>
    <description>Potentially unsigned executable added to startup</description>
    <group>fim,startup,persistence,unsigned</group>
  </rule>
</group>
```