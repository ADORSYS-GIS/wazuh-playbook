### Overview
This document defines the custom Wazuh File Integrity Monitoring (FIM) ruleset for macOS endpoints.
The policy is designed to detect and alert on unauthorized modifications to critical system files, applications, persistence mechanisms, binaries, and configurations.
It strengthens defenses against malware, persistence techniques, privilege escalation, and insider threats.

### Scope

This configuration applies to all macOS systems enrolled in the organization’s endpoint security platform.
It covers system-level, application-level, and user-level assets that attackers may target for compromise or persistence.

### Configuration Directives

#### 3.1. macOS FIM Rules

The following XML rules define alerts for critical system areas:
```
<!-- macOS File Integrity Monitoring Rules -->
 <!-- Save as /var/ossec/etc/rules/macos_fim_rules.xml --> 
 <group name="syscheck,macos,fim,">

 <!-- System Configuration Files -->
<rule id="100100" level="12">
    <if_sid>550,554</if_sid>
    <field name="file">/etc/passwd|/etc/shadow|/etc/sudoers|/etc/hosts</field>
    <description>Critical system configuration file modified on macOS: $(file)</description>
    <group>authentication,system_config,</group>
</rule>

<!-- Launch Daemons and Agents -->
<rule id="100101" level="10">
    <if_sid>550,554</if_sid>
    <field name="file">/System/Library/LaunchDaemons|/Library/LaunchDaemons|/Library/LaunchAgents</field>
    <description>Launch daemon/agent modified on macOS: $(file)</description>
    <group>persistence,startup,</group>
</rule>

<!-- User Launch Agents -->
<rule id="100102" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/Users/.*/Library/LaunchAgents</field>
    <description>User launch agent modified on macOS: $(file)</description>
    <group>persistence,user_startup,</group>
</rule>

<!-- Applications Directory -->
<rule id="100103" level="7">
    <if_sid>550</if_sid>
    <field name="file">/Applications</field>
    <description>Application modified in /Applications: $(file)</description>
    <group>application_change,</group>
</rule>
<rule id="100104" level="10">
    <if_sid>554</if_sid>
    <field name="file">/Applications</field>
    <description>New application added to /Applications: $(file)</description>
    <group>new_application,</group>
</rule>

<!-- System Binaries -->
<rule id="100105" level="12">
    <if_sid>550,554</if_sid>
    <field name="file">/usr/bin|/usr/sbin|/bin|/sbin</field>
    <description>System binary modified on macOS: $(file)</description>
    <group>system_binary,</group>
</rule>

<!-- Kernel Extensions -->
<rule id="100106" level="12">
    <if_sid>550,554</if_sid>
    <field name="file">/System/Library/Extensions|/Library/Extensions</field>
    <description>Kernel extension modified on macOS: $(file)</description>
    <group>kernel_extension,</group>
</rule>

<!-- SSH Configuration -->
<rule id="100107" level="10">
    <if_sid>550,554</if_sid>
    <field name="file">/etc/ssh</field>
    <description>SSH configuration modified on macOS: $(file)</description>
    <group>ssh_config,</group>
</rule>

<!-- User SSH Keys -->
<rule id="100108" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/Users/.*/.ssh</field>
    <description>User SSH configuration modified on macOS: $(file)</description>
    <group>ssh_keys,</group>
</rule>

<!-- Cron Jobs -->
<rule id="100109" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/usr/lib/cron/tabs|/var/cron/tabs</field>
    <description>Cron job modified on macOS: $(file)</description>
    <group>cron_job,</group>
</rule>

<!-- System Preferences -->
<rule id="100110" level="6">
    <if_sid>550</if_sid>
    <field name="file">/Library/Preferences|/System/Library/Preferences</field>
    <description>System preferences modified on macOS: $(file)</description>
    <group>system_preferences,</group>
</rule>

<!-- User Preferences -->
<rule id="100111" level="4">
    <if_sid>550</if_sid>
    <field name="file">/Users/.*/Library/Preferences</field>
    <description>User preferences modified on macOS: $(file)</description>
    <group>user_preferences,</group>
</rule>

<!-- Homebrew -->
<rule id="100112" level="6">
    <if_sid>550,554</if_sid>
    <field name="file">/usr/local/bin|/opt/homebrew/bin</field>
    <description>Homebrew binary modified on macOS: $(file)</description>
    <group>homebrew,package_manager,</group>
</rule>

<!-- Web Server Configurations -->
<rule id="100113" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/etc/apache2|/etc/nginx|/usr/local/etc/nginx</field>
    <description>Web server configuration modified on macOS: $(file)</description>
    <group>web_server,</group>
</rule>

<!-- Database Configurations -->
<rule id="100114" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/usr/local/mysql|/usr/local/var/mysql</field>
    <description>Database configuration modified on macOS: $(file)</description>
    <group>database,</group>
</rule>

<!-- Security Tools -->
<rule id="100115" level="10">
    <if_sid>550,554</if_sid>
    <field name="file">/usr/local/bin/nmap|/usr/local/bin/wireshark</field>
    <description>Security tool modified on macOS: $(file)</description>
    <group>security_tools,</group>
</rule>

<!-- Suspicious File Extensions -->
<rule id="100116" level="10">
    <if_sid>554</if_sid>
    <field name="file">\.sh$|\.py$|\.pl$|\.rb$</field>
    <description>New script file created on macOS: $(file)</description>
    <group>new_script,</group>
</rule>

<!-- Hidden Files in User Directories -->
<rule id="100117" level="8">
    <if_sid>554</if_sid>
    <field name="file">/Users/.*/\.</field>
    <description>New hidden file created in user directory on macOS: $(file)</description>
    <group>hidden_file,</group>
</rule>

<!-- System Library Changes -->
<rule id="100118" level="12">
    <if_sid>550,554</if_sid>
    <field name="file">/System/Library/Frameworks|/usr/lib</field>
    <description>System library modified on macOS: $(file)</description>
    <group>system_library,</group>
</rule>

<!-- Firewall Configuration -->
<rule id="100119" level="10">
    <if_sid>550,554</if_sid>
    <field name="file">/etc/pf.conf</field>
    <description>Firewall configuration modified on macOS: $(file)</description>
    <group>firewall,</group>
</rule>

<!-- Certificate Store -->
<rule id="100120" level="8">
    <if_sid>550,554</if_sid>
    <field name="file">/System/Library/Keychains|/Library/Keychains</field>
    <description>Certificate store modified on macOS: $(file)</description>
    <group>certificates,</group>
</rule>

<!-- Composite Rules for Multiple Changes -->
<rule id="100150" level="12" frequency="5" timeframe="300">
    <if_matched_sid>100100</if_matched_sid>
    <description>Multiple critical system files modified on macOS within 5 minutes</description>
    <group>multiple_changes,attack,</group>
</rule>

<rule id="100151" level="10" frequency="10" timeframe="600">
    <if_matched_sid>100103,100104</if_matched_sid>
    <description>Multiple application changes detected on macOS within 10 minutes</description>
    <group>multiple_app_changes,</group>
</rule>

<!-- File Deletion Rules -->
<rule id="100160" level="10">
    <if_sid>553</if_sid>
    <field name="file">/Applications|/usr/bin|/usr/sbin</field>
    <description>Critical file deleted on macOS: $(file)</description>
    <group>file_deleted,</group>
</rule>

<!-- Permission Changes -->
<rule id="100170" level="8">
    <if_sid>550</if_sid>
    <field name="changed_attributes">permission</field>
    <description>File permissions changed on macOS: $(file)</description>
    <group>permission_change,</group>
</rule>

<!-- Ownership Changes -->
<rule id="100171" level="8">
    <if_sid>550</if_sid>
    <field name="changed_attributes">uid|gid</field>
    <description>File ownership changed on macOS: $(file)</description>
    <group>ownership_change,</group>
</rule>

```