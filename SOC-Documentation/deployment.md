# **Windows Custom Rules Deployment Documentation**

## **1. File Integrity Monitoring - Startup Script Persistence**

### **Rule ID: 600215**
```xml
<rule id="600215" level="8">
  <if_sid>600208</if_sid>
  <field name="file" type="pcre2">(?i)\.ps1$|\.vbs$|\.js$|\.wsf$|\.hta$</field>
  <description>Script file added to startup directory</description>
  <group>fim,startup,persistence,script,</group>
</rule>
```

#### **Business Purpose**
- **Security Use Case**: Detect persistence mechanisms via script files in startup locations
- **Compliance Requirement**: NIST 800-53 SI-3, CIS Control 8.1, MITRE ATT&CK T1547.001
- **Operational Need**: Monitor unauthorized script-based persistence attempts

#### **Technical Specifications**
- **Rule Type**: File Integrity Monitoring (FIM)
- **Parent Rule**: 600208 (Startup directory changes)
- **Trigger Condition**: Script files (PS1, VBS, JS, WSF, HTA) created in startup directories
- **Alert Level**: 8 (High)
- **Fields Monitored**: File path, file extension

#### **Deployment Requirements**
- **Prerequisites**: 
  - Wazuh FIM enabled for startup directories
  - Real-time monitoring on startup folders
- **Target Systems**: All Windows endpoints
- **Dependencies**: Rule 600208 (startup directory baseline)

#### **Monitoring & Response**
- **Severity**: High
- **Initial Response**: 
  1. Investigate file origin and content
  2. Check file digital signature
  3. Verify user context of creation
- **Escalation**: Security team within 1 hour
- **False Positive Rate**: Estimated 2-5% (legitimate software installations)

#### **Compliance Mapping**
- **NIST 800-53**: SI-3, SI-7, CM-3
- **CIS Controls**: 8.1, 8.2
- **MITRE ATT&CK**: T1547.001 (Boot or Logon Autostart Execution)
- **PCI-DSS**: 11.5
- **GDPR**: Article 32

---

## **2. File Integrity Monitoring - Startup Directory Baseline**

### **Rule ID: 600208**
```xml
<rule id="600208" level="4">
  <if_sid>550</if_sid>
  <field name="file" type="pcre2">(?i)\\Startup\\</field>
  <description>File changed in startup directory: $(file)</description>
  <group>fim,startup,</group>
</rule>
```

#### **Business Purpose**
- **Security Use Case**: Baseline monitoring of all startup directory changes
- **Compliance Requirement**: NIST 800-53 CM-3, CM-8
- **Operational Need**: Central logging of all startup location modifications

#### **Technical Specifications**
- **Rule Type**: File Integrity Monitoring (FIM)
- **Parent Rule**: 550 (Generic file change)
- **Trigger Condition**: Any file change in Windows Startup directories
- **Alert Level**: 4 (Informational)
- **Monitoring Scope**: 
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
  - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`

#### **Deployment Requirements**
- **FIM Configuration**:
  ```xml
  <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  ```

#### **Response Procedure**
- **Severity**: Low (Baseline)
- **Action**: Log for audit purposes
- **Use Case**: Parent rule for more specific detection rules

---

## **3. File Integrity Monitoring - System32 Directory**

### **Rule ID: 600200**
```xml
<rule id="600200" level="4">
  <if_sid>550</if_sid>
  <field name="file">C:\\Windows\\System32</field>
  <description>File modified in System32 directory</description>
  <group>fim,system32,</group>
</rule>
```

#### **Business Purpose**
- **Security Use Case**: Detect unauthorized modifications to critical system binaries
- **Compliance Requirement**: NIST 800-53 SI-7, CIS Control 8.5
- **Operational Need**: Monitor core Windows system directory for tampering

#### **Technical Specifications**
- **Rule Type**: File Integrity Monitoring (FIM)
- **Parent Rule**: 550 (Generic file change)
- **Trigger Condition**: Any file modification in System32 directory
- **Alert Level**: 4 (Medium)
- **Critical Files Monitored**: Executables, DLLs, drivers in System32

#### **Deployment Requirements**
- **FIM Configuration**:
  ```xml
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  ```

#### **Monitoring & Response**
- **Severity**: Medium
- **Expected Events**: System updates, patch installations
- **Suspicious Patterns**: 
  - Modifications outside maintenance windows
  - Non-Microsoft signed binaries
  - Changes by non-system accounts

---

## **4. Windows Defender - Threat Blocked**

### **Rule ID: 400051**
```xml
<rule id="400051" level="10">
  <if_sid>62100</if_sid>
  <field name="win.system.eventID">^1117$</field>
  <description>Windows Defender: Threat blocked - $(win.eventdata.threatName)</description>
  <options>no_full_log</options>
  <group>antivirus,threat_blocked,pci_dss_5.1,pci_dss_5.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.3,</group>
</rule>
```

#### **Business Purpose**
- **Security Use Case**: Centralized monitoring of Windows Defender threat prevention
- **Compliance Requirement**: Multiple compliance frameworks (see below)
- **Operational Need**: Real-time alerting on blocked malware and threats

#### **Technical Specifications**
- **Rule Type**: Antivirus Alert
- **Parent Rule**: 62100 (Windows events)
- **Trigger Condition**: Windows Defender Event ID 1117
- **Alert Level**: 10 (Critical)
- **Data Captured**: Threat name, action taken, file path

#### **Deployment Requirements**
- **Prerequisites**:
  - Windows Defender enabled and updated
  - Event log collection configured:
    ```xml
    <localfile>
      <location>Microsoft-Windows-Windows Defender/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    ```

#### **Response Procedure**
- **Severity**: Critical
- **Immediate Actions**:
  1. Isolate affected endpoint if necessary
  2. Investigate threat origin and propagation method
  3. Scan related systems
- **Escalation**: Security team immediately
- **Documentation**: Incident report required

#### **Compliance Mapping**
- **PCI-DSS**: 5.1, 5.2 (Malware protections)
- **GDPR**: Article 32 (Security of processing)
- **HIPAA**: 164.312(b) (Protection from malicious software)
- **NIST 800-53**: SI-3 (Malicious code protection)

---

## **Deployment Instructions**

### **1. Prerequisites**
- Wazuh agent 4.13+ installed on Windows endpoints
- File Integrity Monitoring enabled in agent configuration
- Windows Event Log collection configured
- Sufficient storage for alert retention

### **2. Configuration Steps**

#### **Agent Configuration (ossec.conf)**
```xml
<agent_config os="Windows">
  <syscheck>
    <disabled>no</disabled>
    <frequency>60</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    
    <!-- Startup directories -->
    <directories check_all="yes" realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    
    <!-- System32 directory -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  </syscheck>

  <!-- Windows Defender events -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

#### **Rules Deployment**
1. Add rules to `/var/ossec/etc/rules/local_rules.xml` on Wazuh manager
2. Restart Wazuh manager: `systemctl restart wazuh-manager`
3. Verify rule loading in `/var/ossec/logs/ossec.log`

### **3. Testing Procedure**
```powershell
# Test Startup Script Rule (600215)
"Test script" | Out-File "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\test_script.ps1"
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\test_script.ps1" -ErrorAction SilentlyContinue

# Test System32 Rule (600200) - Use with caution
"Test" | Out-File "C:\Windows\System32\test_fim.txt" -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\System32\test_fim.txt" -ErrorAction SilentlyContinue
```

### **4. Validation Checklist**
- [ ] Rules loaded in Wazuh manager (check ossec.log)
- [ ] FIM monitoring active on target directories
- [ ] Windows Defender events being collected
- [ ] Test alerts generated successfully
- [ ] Alert routing configured properly
- [ ] Response procedures documented

### **5. Maintenance Schedule**
- **Weekly**: Review false positives and tune rules
- **Monthly**: Update compliance mappings
- **Quarterly**: Full rule review and testing
- **Annually**: Compliance audit preparation

---

## **Review Notes**

1. **Rule 600215** provides high-value detection for script-based persistence
2. **Rule 600200** may generate noise during Windows updates
3. **Rule 400051** is critical for compliance reporting
4. All rules have been technically validated during testing
