

# macOS Security Monitoring Rules for OSSEC/Wazuh

This document outlines a comprehensive set of security monitoring rules for **macOS environments**, specifically designed for use with **OSSEC/Wazuh**.
It aims to provide **advanced threat detection capabilities** while **minimizing false positives** through intelligent noise reduction.

---

## Coverage Areas

* **Critical System Events**: Monitoring for kernel panics, fatal errors, and violations of System Integrity Protection (SIP).
* **Keychain Security**: Tracking access to the keychain to detect potential credential theft or unauthorized export of sensitive data.
* **Gatekeeper Bypasses**: Identifying attempts to circumvent macOS's application security feature.
* **Root Access Monitoring**: Logging and alerting on the use of the root account to track privileged access.
* **File Integrity Monitoring (FIM)**: Watching for unauthorized changes to critical system files, configurations, application launch services, and kernel extensions.
* **SSH Security**: Monitoring for modifications to SSH configurations and authorized keys.
* **Privilege Escalation**: Detecting changes to the sudoers file, which could indicate an attempt to gain elevated permissions.
* **Log Tampering**: Alerting on attempts to clear or manipulate system logs to cover tracks.

---

## Key Features

* **Intelligent noise reduction** to filter out legitimate administrative and system activities.
* **Time-based rules** to ignore routine maintenance.
* **Severity-level-based alerting** (levels 0–15).
* **Compliance mapping** to PCI DSS, HIPAA, GDPR, and NIST 800-53.

---

## Rule ID Ranges:
- 100001-100114: Complete macOS security monitoring coverage

## Ruleset (XML)

```xml
<group name="macos,syslog,">
 	<!-- Critical System Events -->
    <rule id="100001" level="12">
    <if_group >syslog</if_group>
    <match >kernel</match>
    <regex >panic|kernel trap|fatal|critical</regex>
    <description >macOS: Critical kernel panic or fatal error detected</description>
    <group >system_error</group>
    </rule>
    <!-- Exclude normal kernel messages that contain 'critical' but aren't actual errors -->
    <rule id="100002" level="0">
    <if_sid >100001</if_sid>
    <regex >critical section|critical path|critical region</regex>
    <description >macOS: Normal kernel critical section operations - noise
    reduction</description>
    </rule>
    <!-- Exclude thermal management messages -->
    <rule id="100003" level="0">
    <if_sid >100001</if_sid>
    <regex >thermal|temperature|cooling</regex>
    <description >macOS: Thermal management messages - noise reduction</description>
    </rule>
    <!-- Exclude USB/hardware disconnect messages -->
    <rule id="100004" level="0">
    <if_sid >100001</if_sid>
    <regex >USB.*disconnect|device.*removed|hardware.*disconnect</regex>
    <description >macOS: Normal hardware disconnect messages - noise
    reduction</description>
    </rule>
    <!-- System Integrity Protection (SIP) Violations -->
    <rule id="100005" level="12">
    <if_group >syslog</if_group>
    <match >kernel</match>
    <regex >System Integrity Protection|SIP violation</regex>
    <description >macOS: System Integrity Protection violation detected</description>
    <group >system_error</group>
    </rule>
    <!-- Exclude SIP status checks and informational messages -->
    <rule id="100006" level="0">
    <if_sid >100005</if_sid>
    <regex >SIP status|SIP enabled|SIP disabled|checking SIP|SIP configuration</regex>
    <description >macOS: SIP status check or configuration message - noise
    reduction</description>
    </rule>
    <!-- Exclude legitimate developer tools SIP interactions -->
    <rule id="100007" level="0">
    <if_sid >100005</if_sid>
    <regex >Xcode|lldb|dtrace|dtruss|developer</regex>
    <description >macOS: Legitimate developer tool SIP interaction - noise
    reduction</description>
    </rule>
    <!-- Exclude system update related SIP messages -->
    <rule id="100008" level="0">
    <if_sid >100005</if_sid>
    <regex >Software Update|system update|macOS update|installer</regex>
    <description >macOS: System update related SIP message - noise
    reduction</description>
    </rule>
    <!-- Lower severity for SIP warnings vs actual violations -->
    <rule id="100009" level="8">
    <if_sid >100005</if_sid>
    <regex >SIP warning|SIP notice|may be restricted</regex>
    <description >macOS: SIP warning or notice (not violation)</description>
    <group
    >system_error,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.
    7,tsc_CC7.1</group>
    </rule>
    <!-- Exclude recovery mode SIP operations -->
    <rule id="100010" level="0">
    <if_sid >100005</if_sid>
    <regex >recovery mode|recovery boot|csrutil</regex>
    <description >macOS: Recovery mode SIP operation - noise reduction</description>
    </rule>

    <!-- Keychain Access with Noise Reduction -->
    <rule id="100011" level="8">
    <if_group >syslog</if_group>
    <match >SecurityAgent</match>
    <regex >keychain|password</regex>
    <description >macOS: Keychain access detected</description>
    <group
    >access_control,pci_dss_10.2.1,gpg13_7.8,gdpr_IV_32.2,hipaa_164.312.a.2.I,nist_800_53_
    AC.2,tsc_CC6.1</group>
    </rule>
    <!-- Exclude normal keychain operations -->
    <rule id="100012" level="0">
    <if_sid >100011</if_sid>
    <regex >keychain.*unlock|normal.*access|automatic.*unlock|login.*keychain</regex>
    <description >macOS: Normal keychain unlock/access - noise reduction</description>
    </rule>
    <!-- Exclude system applications keychain access -->
    <rule id="100013" level="0">
    <if_sid >100011</if_sid>
    <regex >Safari|Mail|Calendar|Contacts|System Preferences|loginwindow</regex>
    <description >macOS: System application keychain access - noise reduction</description>
    </rule>
    <!-- Exclude password autofill operations -->
    <rule id="100014" level="0">
    <if_sid >100011</if_sid>
    <regex >autofill|auto-fill|password.*suggestion|iCloud.*keychain</regex>
    <description >macOS: Password autofill operation - noise reduction</description>
    </rule>
    <!-- Higher severity for suspicious keychain access -->
    <rule id="100015" level="12">
    <if_sid >100011</if_sid>
    <regex
    >keychain.*export|keychain.*dump|password.*extract|unauthorized.*access</regex>
    <description >macOS: Suspicious keychain export or unauthorized access</description>
    <group
    >access_control,credential_theft,pci_dss_10.2.1,gpg13_7.8,gdpr_IV_32.2,hipaa_164.312.a.
    2.I,nist_800_53_AC.2,tsc_CC6.1</group>
    </rule>
    <!-- Exclude keychain repair operations -->
    <rule id="100016" level="0">
    <if_sid >100011</if_sid>
    <regex >keychain.*repair|keychain.*verify|keychain.*first.*aid</regex>
    <description >macOS: Keychain repair/verification operation - noise
    reduction</description>
    </rule>
    <!-- Lower severity for keychain creation -->
    <rule id="100017" level="4">
    <if_sid >100011</if_sid>
    <regex >keychain.*create|new.*keychain|keychain.*setup</regex>
    <description >macOS: New keychain creation</description>
    <group>access_control,pci_dss_10.2.1,gpg13_7.8,gdpr_IV_32.2,hipaa_164.312.a.2.I,nist_800_53_
    AC.2,tsc_CC6.1</group>
    </rule>
    <!-- Exclude time-based normal operations -->
    <rule id="100018" level="0">
    <if_sid >100011</if_sid>
    <time >00:00-06:00</time>
    <regex >backup|sync|maintenance</regex>
    <description >macOS: Scheduled keychain maintenance operations - noise
    reduction</description>
    </rule>
    <!-- Gatekeeper Bypass with Noise Reduction -->
    <rule id="100019" level="10">
    <if_group >syslog</if_group>
    <match >Gatekeeper</match>
    <regex >bypass|disabled|override</regex>
    <description >macOS: Gatekeeper security bypass detected</description>
    <group>system_error,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.
    3,tsc_CC7.1</group>
    </rule>
    <!-- Exclude legitimate administrative Gatekeeper changes -->
    <rule id="100020" level="0">
    <if_sid >100019</if_sid>
    <regex >System Preferences|spctl.*--master-disable|administrator.*disabled</regex>
    <description >macOS: Administrative Gatekeeper configuration change - noise
    reduction</description>
    </rule>
     <!-- Exclude developer mode operations -->
    <rule id="100021" level="0">
    <if_sid >100019</if_sid>
    <regex >developer.*mode|Xcode|development.*certificate|codesign.*override</regex>
    <description >macOS: Developer mode Gatekeeper override - noise
    reduction</description>
    </rule>
      <!-- Exclude system updates and installers -->
    <rule id="100022" level="0">
    <if_sid >100019</if_sid>
    <regex >Software Update|macOS.*installer|Apple.*installer|system.*update</regex>
    <description >macOS: System update Gatekeeper override - noise reduction</description>
    </rule>
     <!-- Higher severity for malicious bypass attempts -->
    <rule id="100023" level="12">
    <if_sid >100019</if_sid>
    <regex >malware|trojan|suspicious.*bypass|unauthorized.*override</regex>
    <description >macOS: Malicious Gatekeeper bypass attempt detected</description>
    <group
    >system_error,malware,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_80
    0_53_SI.3,tsc_CC7.1</group>
    </rule>
     <!-- Exclude temporary bypass for known applications -->
    <rule id="100024" level="0">
    <if_sid >100019</if_sid>
    <regex >temporary.*override|one.*time.*bypass|user.*approved</regex>
    <description >macOS: User-approved temporary Gatekeeper bypass - noise
    reduction</description>
    </rule>
     <!-- Lower severity for informational messages -->
    <rule id="100025" level="4">
    <if_sid >100019</if_sid>
    <regex >Gatekeeper.*status|checking.*Gatekeeper|Gatekeeper.*enabled</regex>
    <description >macOS: Gatekeeper status check or informational message</description>
    <group
    >system_error,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SI.
    3,tsc_CC7.1</group>
    </rule>
     <!-- Exclude enterprise management tools -->
    <rule id="100026" level="0">
    <if_sid >100019</if_sid>
    <regex >MDM|Jamf|SCCM|enterprise.*policy|corporate.*override</regex>
    <description >macOS: Enterprise management Gatekeeper policy - noise
    reduction</description>
    </rule>
      <!-- Root Access Events with Noise Reduction -->
    <rule id="100036" level="10">
    <if_group >authentication_success</if_group>
    <user >root</user>
    <description >macOS: Root user login detected</description>
    <group
    >authentication,pci_dss_10.2.5,gpg13_7.8,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.
    14,nist_800_53_AC.7,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
    </rule>
     <!-- Exclude system processes and daemons -->
    <rule id="100037" level="0">
    <if_sid >100036</if_sid>
    <regex >launchd|kernel_task|kextd|mds|mdworker|systemstats</regex>
    <description >macOS: System process root access - noise reduction</description>
    </rule>
    <!-- Exclude scheduled system maintenance -->
    <rule id="100038" level="0">
    <if_sid >100036</if_sid>
    <time >02:00-05:00</time>
    <regex >periodic|maintenance|cleanup|cron</regex>
    <description >macOS: Scheduled maintenance root access - noise
    reduction</description>
    </rule>
    <!-- Exclude system updates and installers -->
    <rule id="100039" level="0">
    <if_sid >100036</if_sid>
    <regex >Software Update|installer|pkgutil|system_profiler</regex>
    <description >macOS: System update root access - noise reduction</description>
    </rule>
    <!-- Higher severity for interactive root login -->
    <rule id="100040" level="12">
    <if_sid >100036</if_sid>
    <regex >ssh|console|terminal|interactive|login</regex>
    <description >macOS: Interactive root login detected - high risk</description>
    <group
    >authentication,privilege_escalation,pci_dss_10.2.5,gpg13_7.8,gdpr_IV_32.2,hipaa_164.31
    2.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
    </rule>
    <!-- Exclude Apple system services -->
    <rule id="100041" level="0">
    <if_sid >100036</if_sid>
    <regex >com\.apple\.|/System/Library/|Apple.*service</regex>
    <description >macOS: Apple system service root access - noise reduction</description>
    </rule>
    <!-- Exclude backup and sync operations -->
    <rule id="100042" level="0">
    <if_sid >100036</if_sid>
    <regex >Time Machine|backupd|syncdefaultsd|cloudd</regex>
    <description >macOS: Backup/sync service root access - noise reduction</description>
    </rule>
    <!-- Lower severity for sudo escalation -->
    <rule id="100043" level="6">
    <if_sid >100036</if_sid>
    <regex >sudo|su -</regex>
    <description >macOS: Root access via sudo/su</description>
    <group
    >authentication,privilege_escalation,pci_dss_10.2.5,gpg13_7.8,gdpr_IV_32.2,hipaa_164.31
    2.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
    </rule>
    <!-- Exclude security services -->
    <rule id="100044" level="0">
    <if_sid >100036</if_sid>
    <regex >securityd|SecurityAgent|authd|opendirectoryd</regex>
    <description >macOS: Security service root access - noise reduction</description>
    </rule>
    <!-- FIM Rules for macOS -->
    <!-- System Binary Modifications with Noise Reduction -->
    <rule id="100045" level="12">
    <if_group >syscheck</if_group>
    <field name="file">/usr/bin|/usr/sbin|/bin|/sbin</field>
    <description >macOS FIM: Critical system binary modified</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude system updates and installers -->
    <rule id="100046" level="0">
    <if_sid >100045</if_sid>
    <field name="uname">_installer|root</field>
    <field name="gname">wheel|admin</field>
    <description >macOS FIM: System update binary modification - noise
    reduction</description>
    </rule>
      <!-- Exclude package manager operations -->
    <rule id="100047" level="0">
    <if_sid >100045</if_sid>
    <field name="audit_user">brew|port|fink</field>
    <description >macOS FIM: Package manager binary installation - noise
    reduction</description>
    </rule>
    <!-- Higher severity for unauthorized modifications -->
    <rule id="100048" level="15">
    <if_sid >100045</if_sid>
    <field name="event_type">modified</field>
    <field name="changed_attributes">size|md5|sha1</field>
    <description >macOS FIM: Unauthorized system binary modification
    detected</description>
    <group
    >syscheck,file_integrity,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.
    1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100049" level="6">
    <if_sid >100045</if_sid>
    <field name="event_type">modified</field>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: System binary permission change</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude Xcode and development tools -->
    <rule id="100050" level="0">
    <if_sid >100045</if_sid>
    <field name="file">/usr/bin/xcode|/usr/bin/swift|/usr/bin/clang</field>
    <description >macOS FIM: Development tools binary update - noise
    reduction</description>
    </rule>
    <!-- Exclude time-based system operations -->
    <rule id="100051" level="0">
    <if_sid >100045</if_sid>
    <field name="audit_user">_system|root</field>
    <time >02:00-05:00</time>
    <description >macOS FIM: Scheduled system binary maintenance - noise
    reduction</description>
    </rule>
    <!-- Alert on new binary creation -->
    <rule id="100052" level="10">
    <if_sid >100045</if_sid>
    <field name="event_type">added</field>
    <description >macOS FIM: New system binary created</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
      <!-- Exclude Apple signed binaries -->
    <rule id="100053" level="0">
    <if_sid >100045</if_sid>
    <field name="audit_user">_installer</field>
    <field name="file">/usr/bin/.*Apple|/usr/sbin/.*Apple</field>
    <description >macOS FIM: Apple signed binary update - noise reduction</description>
    </rule>
    <!-- System Configuration Files with Noise Reduction -->
    <rule id="100054" level="10">
    <if_group >syscheck</if_group>
    <field name="file">/etc|/private/etc</field>
    <description >macOS FIM: System configuration file modified</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude system updates and installers -->
    <rule id="100055" level="0">
    <if_sid >100054</if_sid>
    <field name="uname">_installer|root</field>
    <field name="gname">wheel|admin</field>
    <description >macOS FIM: System update configuration change - noise
    reduction</description>
    </rule>
    <!-- Exclude log rotation and maintenance -->
    <rule id="100056" level="0">
    <if_sid >100054</if_sid>
    <field name="file">/etc/newsyslog.conf|/private/etc/newsyslog.conf</field>
    <field name="audit_user">_system|root</field>
    <description >macOS FIM: Log rotation configuration - noise reduction</description>
    </rule>
    <!-- Exclude network configuration updates -->
    <rule id="100057" level="0">
    <if_sid >100054</if_sid>
    <field name="file">/etc/resolv.conf|/private/etc/resolv.conf</field>
    <field name="audit_user">_networkd|_system</field>
    <description >macOS FIM: Network configuration update - noise reduction</description>
    </rule>
    <!-- Higher severity for security-critical files -->
    <rule id="100058" level="12">
    <if_sid >100054</if_sid>
    <field name="file">/etc/sudoers|/private/etc/sudoers|/etc/ssh|/private/etc/ssh</field>
    <description >macOS FIM: Critical security configuration modified</description>
    <group
    >syscheck,file_integrity,privilege_escalation,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa
    _164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude time synchronization -->
    <rule id="100059" level="0">
    <if_sid >100054</if_sid>
    <field name="file">/etc/ntp.conf|/private/etc/ntp.conf</field>
    <field name="audit_user">_ntp|root</field>
    <description >macOS FIM: Time synchronization configuration - noise
    reduction</description>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100060" level="6">
    <if_sid >100054</if_sid>
    <field name="event_type">modified</field>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: Configuration file permission change</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
     <!-- Exclude scheduled maintenance -->
    <rule id="100061" level="0">
    <if_sid >100054</if_sid>
    <time >02:00-05:00</time>
    <field name="audit_user">_system|root</field>
    <description >macOS FIM: Scheduled configuration maintenance - noise
    reduction</description>
    </rule>
    <!-- Exclude package manager configurations -->
    <rule id="100062" level="0">
    <if_sid >100054</if_sid>
    <field name="file">/etc/paths|/private/etc/paths</field>
    <field name="audit_user">brew|port|fink</field>
    <description >macOS FIM: Package manager configuration - noise
    reduction</description>
    </rule>
    <!-- Alert on new configuration files -->
    <rule id="100063" level="8">
    <if_sid >100054</if_sid>
    <field name="event_type">added</field>
    <description >macOS FIM: New system configuration file created</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- LaunchDaemons and LaunchAgents with Noise Reduction -->
    <rule id="100064" level="12">
    <if_group >syscheck</if_group>
    <field
    name="file">/System/Library/LaunchDaemons|/Library/LaunchDaemons|/System/Library/Lau
    nchAgents|/Library/LaunchAgents</field>
    <description >macOS FIM: Launch daemon/agent modified - potential persistence
    mechanism</description>
    <group
    >syscheck,file_integrity,persistence,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.31
    2.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude Apple system updates and installers -->
    <rule id="100065" level="0">
    <if_sid >100064</if_sid>
    <field name="uname">_installer|root</field>
    <field name="file">com\.apple\.|Apple</field>
    <description >macOS FIM: Apple system daemon/agent update - noise
    reduction</description>
    </rule>
    <!-- Exclude legitimate software installations -->
    <rule id="100066" level="0">
    <if_sid >100064</if_sid>
    <field name="process">installer|pkgutil|Software Update</field>
    <description >macOS FIM: Legitimate software installation daemon/agent - noise
    reduction</description>
    </rule>
    <!-- Higher severity for user-writable locations -->
    <rule id="100067" level="15">
    <if_sid >100064</if_sid>
    <field name="file">/Library/LaunchAgents|/Library/LaunchDaemons</field>
    <field name="event_type">added|modified</field>
    <description >macOS FIM: Critical - User-writable launch daemon/agent
    modified</description>
    <group
    >syscheck,file_integrity,persistence,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipa
    a_164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100068" level="6">
    <if_sid >100064</if_sid>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: Launch daemon/agent permission change</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude known legitimate applications -->
    <rule id="100069" level="0">
    <if_sid >100064</if_sid>
    <field
    name="file">com\.microsoft\.|com\.adobe\.|com\.google\.|com\.dropbox\.|com\.slack\.</field>
    <description >macOS FIM: Known legitimate application daemon/agent - noise
    reduction</description>
    </rule>
    <!-- Exclude development tools -->
    <rule id="100070" level="0">
    <if_sid >100064</if_sid>
    <field name="file">com\.apple\.xcode|developer|Xcode</field>
    <description >macOS FIM: Development tools daemon/agent - noise
    reduction</description>
    </rule>
     <!-- Alert on suspicious file names -->
    <rule id="100071" level="15">
    <if_sid >100064</if_sid>
    <field name="file">backdoor|malware|trojan|rootkit|hidden</field>
    <description >macOS FIM: Suspicious launch daemon/agent name detected</description>
    <group
    >syscheck,file_integrity,persistence,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipa
    a_164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude time-based system maintenance -->
    <rule id="100072" level="0">
    <if_sid >100064</if_sid>
    <time >02:00-05:00</time>
    <field name="process">periodic|maintenance|cleanup</field>
    <description >macOS FIM: Scheduled maintenance daemon/agent operations - noise
    reduction</description>
    </rule>
    <!-- Monitor deletions separately -->
    <rule id="100073" level="10">
    <if_sid >100064</if_sid>
    <field name="event_type">deleted</field>
    <description >macOS FIM: Launch daemon/agent deleted</description>
    <group
    >syscheck,file_integrity,persistence,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.31
    2.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Kernel Extensions with Noise Reduction -->
    <rule id="100074" level="12">
    <if_group >syscheck</if_group>
    <field name="file">/System/Library/Extensions|/Library/Extensions</field>
    <description >macOS FIM: Kernel extension modified - critical system
    change</description>
    <group
    >syscheck,file_integrity,kernel,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,
    nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude Apple system updates and installers -->
    <rule id="100075" level="0">
    <if_sid >100074</if_sid>
    <field name="uname">_installer|root</field>
    <field name="file">com\.apple\.|Apple</field>
    <description >macOS FIM: Apple kernel extension update - noise reduction</description>
    </rule>
    <!-- Exclude macOS system updates -->
    <rule id="100076" level="0">
    <if_sid >100074</if_sid>
    <field name="process">Software Update|installer|pkgutil|system_profiler</field>
    <description >macOS FIM: System update kernel extension - noise
    reduction</description>
    </rule>
    <!-- Higher severity for third-party kernel extensions -->
    <rule id="100077" level="15">
    <if_sid >100074</if_sid>
    <field name="file">/Library/Extensions</field>
    <field name="event_type">added|modified</field>
    <description >macOS FIM: Critical - Third-party kernel extension modified</description>
    <group
    >syscheck,file_integrity,kernel,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164
    .312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100078" level="6">
    <if_sid >100074</if_sid>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: Kernel extension permission change</description>
    <group
    >syscheck,file_integrity,kernel,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,
    nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude known legitimate drivers -->
    <rule id="100079" level="0">
    <if_sid >100074</if_sid>
    <field name="file">VirtualBox|VMware|Parallels|NVIDIA|AMD|Intel</field>
    <description >macOS FIM: Known legitimate driver extension - noise
    reduction</description>
    </rule>
    <!-- Exclude security software kernel extensions -->
    <rule id="100080" level="0">
    <if_sid >100074</if_sid>
    <field name="file">ClamAV|Sophos|Bitdefender|ESET|Malwarebytes|CrowdStrike</field>
    <description >macOS FIM: Security software kernel extension - noise
    reduction</description>
    </rule>
      <!-- Alert on suspicious kernel extension names -->
    <rule id="100081" level="15">
    <if_sid >100074</if_sid>
    <field name="file">backdoor|malware|trojan|rootkit|keylogger</field>
    <description >macOS FIM: Suspicious kernel extension name detected</description>
    <group
    >syscheck,file_integrity,kernel,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164
    .312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude time-based system maintenance -->
    <rule id="100082" level="0">
    <if_sid >100074</if_sid>
    <time >02:00-05:00</time>
    <field name="process">periodic|maintenance|cleanup|kextcache</field>
    <description >macOS FIM: Scheduled kernel extension maintenance - noise
    reduction</description>
    </rule>
    <!-- Monitor kernel extension deletions -->
    <rule id="100083" level="10">
    <if_sid >100074</if_sid>
    <field name="event_type">deleted</field>
    <description >macOS FIM: Kernel extension deleted</description>
    <group
    >syscheck,file_integrity,kernel,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,
    nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude kext cache rebuilds -->
    <rule id="100084" level="0">
    <if_sid >100074</if_sid>
    <field name="process">kextcache|kextload|kextunload</field>
    <description >macOS FIM: Kernel extension cache operations - noise
    reduction</description>
    </rule>
    <!-- SSH Configuration with Noise Reduction -->
    <rule id="100085" level="10">
    <if_group >syscheck</if_group>
    <field name="file">/etc/ssh|/private/etc/ssh</field>
    <description >macOS FIM: SSH configuration file modified</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude system updates and installers -->
    <rule id="100086" level="0">
    <if_sid >100085</if_sid>
    <field name="uname">_installer|root</field>
    <field name="process">installer|pkgutil|Software Update</field>
    <description >macOS FIM: System update SSH configuration - noise
    reduction</description>
    </rule>
    <!-- Higher severity for sshd_config modifications -->
    <rule id="100087" level="12">
    <if_sid >100085</if_sid>
    <field name="file">sshd_config</field>
    <field name="event_type">modified</field>
    <description >macOS FIM: Critical - SSH daemon configuration modified</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for host key regeneration -->
    <rule id="100088" level="6">
    <if_sid >100085</if_sid>
    <field name="file">ssh_host_.*_key</field>
    <field name="event_type">modified|added</field>
    <description >macOS FIM: SSH host key regenerated</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100089" level="4">
    <if_sid >100085</if_sid>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: SSH file permission change</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude SSH key generation during setup -->
    <rule id="100090" level="0">
    <if_sid >100085</if_sid>
    <field name="process">ssh-keygen|sshd</field>
    <field name="file">ssh_host_.*_key</field>
    <description >macOS FIM: SSH key generation during setup - noise
    reduction</description>
    </rule>
     <!-- Alert on authorized_keys modifications -->
    <rule id="100091" level="12">
    <if_sid >100085</if_sid>
    <field name="file">authorized_keys</field>
    <field name="event_type">modified|added</field>
    <description >macOS FIM: SSH authorized_keys file modified</description>
    <group
    >syscheck,file_integrity,ssh,authentication,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_
    164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude system maintenance operations -->
    <rule id="100092" level="0">
    <if_sid >100085</if_sid>
    <time >02:00-05:00</time>
    <field name="process">periodic|maintenance|cleanup</field>
    <description >macOS FIM: Scheduled SSH maintenance - noise reduction</description>
    </rule>
    <!-- Monitor SSH configuration deletions -->
    <rule id="100093" level="12">
    <if_sid >100085</if_sid>
    <field name="event_type">deleted</field>
    <description >macOS FIM: SSH configuration file deleted</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude known_hosts updates -->
    <rule id="100094" level="4">
    <if_sid >100085</if_sid>
    <field name="file">known_hosts</field>
    <field name="event_type">modified</field>
    <description >macOS FIM: SSH known_hosts file updated</description>
    <group
    >syscheck,file_integrity,ssh,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nis
    t_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Sudoers File with Noise Reduction -->
    <rule id="100095" level="12">
    <if_group >syscheck</if_group>
    <field name="file">/etc/sudoers|/private/etc/sudoers</field>
    <description >macOS FIM: Sudoers file modified - privilege escalation risk</description>
    <group
    >syscheck,file_integrity,privilege_escalation,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa
    _164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude system updates and installers -->
    <rule id="100096" level="0">
    <if_sid >100095</if_sid>
    <field name="uname">_installer|root</field>
    <field name="process">installer|pkgutil|Software Update</field>
    <description >macOS FIM: System update sudoers modification - noise
    reduction</description>
    </rule>
    <!-- Higher severity for unauthorized modifications -->
    <rule id="100097" level="15">
    <if_sid >100095</if_sid>
    <field name="event_type">modified</field>
    <field name="changed_attributes">size|md5|sha1</field>
    <description >macOS FIM: Critical - Unauthorized sudoers file content
    modified</description>
    <group
    >syscheck,file_integrity,privilege_escalation,malware,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.
    7.d,hipaa_164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Lower severity for permission changes only -->
    <rule id="100098" level="6">
    <if_sid >100095</if_sid>
    <field name="changed_attributes">permission|uid|gid</field>
    <description >macOS FIM: Sudoers file permission change</description>
    <group
    >syscheck,file_integrity,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa_164.312.c.1,nist_80
    0_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude legitimate administrative tools -->
    <rule id="100099" level="0">
    <if_sid >100095</if_sid>
    <field name="process">visudo|System Preferences|dscl</field>
    <description >macOS FIM: Legitimate administrative sudoers modification - noise
    reduction</description>
    </rule>
    <!-- Exclude enterprise management tools -->
    <rule id="100100" level="0">
    <if_sid >100095</if_sid>
    <field name="process">Jamf|SCCM|MDM|enterprise</field>
    <description >macOS FIM: Enterprise management sudoers modification - noise
    reduction</description>
    </rule>
    <!-- Alert on sudoers.d directory changes -->
    <rule id="100101" level="10">
    <if_sid >100095</if_sid>
    <field name="file">/etc/sudoers.d|/private/etc/sudoers.d</field>
    <description >macOS FIM: Sudoers.d directory file modified</description>
    <group
    >syscheck,file_integrity,privilege_escalation,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa
    _164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Monitor sudoers file deletions -->
    <rule id="100102" level="15">
    <if_sid >100095</if_sid>
    <field name="event_type">deleted</field>
    <description >macOS FIM: Critical - Sudoers file deleted</description>
    <group
    >syscheck,file_integrity,privilege_escalation,pci_dss_11.5,gpg13_4.11,gdpr_IV_35.7.d,hipaa
    _164.312.c.1,nist_800_53_SI.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.1</group>
    </rule>
    <!-- Exclude backup operations -->
    <rule id="100103" level="0">
    <if_sid >100095</if_sid>
    <field name="process">cp|backup|rsync</field>
    <field name="file">sudoers.bak|sudoers.backup</field>
    <description >macOS FIM: Sudoers backup operation - noise reduction</description>
    </rule>
    <!-- Time-based filtering for maintenance -->
    <rule id="100104" level="0">
    <if_sid >100095</if_sid>
    <time >02:00-05:00</time>
    <field name="process">periodic|maintenance|cleanup</field>
    <description >macOS FIM: Scheduled sudoers maintenance - noise
    reduction</description>
    </rule>
    <!-- System Log Cleared with Noise Reduction -->
    <rule id="100105" level="10">
    <if_group >syslog</if_group>
    <match >syslogd</match>
    <regex >log cleared|log rotated|log deleted</regex>
    <description >macOS: System log cleared or deleted</description>
    <group
    >log_cleared,pci_dss_10.5.2,gpg13_10.1,gdpr_IV_30.1.g,hipaa_164.312.b,nist_800_53_AU
    .9,tsc_CC7.2</group>
    </rule>
    <!-- Exclude normal log rotation -->
    <rule id="100106" level="0">
    <if_sid >100105</if_sid>
    <regex >newsyslog|logrotate|automatic rotation|scheduled rotation</regex>
    <description >macOS: Normal log rotation - noise reduction</description>
    </rule>
    <!-- Exclude system maintenance operations -->
    <rule id="100107" level="0">
    <if_sid >100105</if_sid>
    <time >02:00-05:00</time>
    <regex >maintenance|periodic|cleanup|automatic</regex>
    <description >macOS: Scheduled log maintenance - noise reduction</description>
    </rule>
    <!-- Higher severity for manual log clearing -->
    <rule id="100108" level="12">
    <if_sid >100105</if_sid>
    <regex >manually cleared|user cleared|rm.*\.log|truncate.*log</regex>
    <description >macOS: Manual log clearing detected - potential evidence
    tampering</description>
    <group
    >log_cleared,evidence_tampering,pci_dss_10.5.2,gpg13_10.1,gdpr_IV_30.1.g,hipaa_164.3
    12.b,nist_800_53_AU.9,tsc_CC7.2</group>
    </rule>
    <!-- Exclude disk space management -->
    <rule id="100109" level="0">
    <if_sid >100105</if_sid>
    <regex >disk space|storage full|space management|low disk</regex>
    <description >macOS: Log clearing due to disk space management - noise
    reduction</description>
    </rule>
    <!-- Lower severity for normal log archiving -->
    <rule id="100110" level="4">
    <if_sid >100105</if_sid>
    <regex >archived|compressed|gzipped|log archive</regex>
    <description >macOS: Log archiving operation</description>
    <group
    >log_cleared,pci_dss_10.5.2,gpg13_10.1,gdpr_IV_30.1.g,hipaa_164.312.b,nist_800_53_AU
    .9,tsc_CC7.2</group>
    </rule>
    <!-- Exclude system startup log initialization -->
    <rule id="100111" level="0">
    <if_sid >100105</if_sid>
    <regex >startup|boot|initialization|syslogd.*start</regex>
    <description >macOS: System startup log initialization - noise reduction</description>
    </rule>
    <!-- Alert on multiple log clearing events -->
    <rule id="100112" level="12" frequency="3" timeframe="300">
    <if_matched_sid >100105</if_matched_sid>
    <same_source_ip />
    <description >macOS: Multiple log clearing events - possible log tampering</description>
    <group
    >log_cleared,correlation,pci_dss_10.5.2,gpg13_10.1,gdpr_IV_30.1.g,hipaa_164.312.b,nist_
    800_53_AU.9,tsc_CC7.2</group>
    </rule>
     <!-- Exclude known maintenance applications -->
    <rule id="100113" level="0">
    <if_sid >100105</if_sid>
    <regex >CleanMyMac|Onyx|Maintenance|DiskUtility|Console</regex>
    <description >macOS: Known maintenance application log operations - noise
    reduction</description>
    </rule>
     <!-- Exclude configuration changes -->
    <rule id="100114" level="0">
    <if_sid >100105</if_sid>
    <regex >configuration change|syslog.*config|facility.*change</regex>
    <description >macOS: Syslog configuration change - noise reduction</description>
    </rule>


</group>
```
