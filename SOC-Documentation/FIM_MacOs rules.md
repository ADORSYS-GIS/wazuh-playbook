### Overview
This document defines the custom Wazuh File Integrity Monitoring (FIM) ruleset for macOS endpoints.
The policy is designed to detect and alert on unauthorized modifications to critical system files, applications, persistence mechanisms, binaries, and configurations.
It strengthens defenses against malware, persistence techniques, privilege escalation, and insider threats.

### Scope

This configuration applies to all macOS systems enrolled in the organization’s endpoint security platform.
It covers system-level, application-level, and user-level assets that attackers may target for compromise or persistence.

### Configuration Directives
3.1. Monitored Directories & Files

The following directories and files are monitored for content modifications, additions, deletions, permission changes, and ownership changes. Each monitored path is tied to custom Wazuh rules that trigger alerts at appropriate severity levels.
```
<!-- 3.1.1. Critical System Configurations -->
<directories>/etc/passwd</directories>
<directories>/etc/shadow</directories>
<directories>/etc/sudoers</directories>
<directories>/etc/hosts</directories>

<!-- 3.1.2. System Launch Daemons & Agents -->
<directories>/System/Library/LaunchDaemons</directories>
<directories>/Library/LaunchDaemons</directories>
<directories>/Library/LaunchAgents</directories>

<!-- 3.1.3. User Launch Agents -->
<directories>/Users/*/Library/LaunchAgents</directories>

<!-- 3.1.4. Applications -->
<directories>/Applications</directories>

<!-- 3.1.5. System Binaries -->
<directories>/usr/bin</directories>
<directories>/usr/sbin</directories>
<directories>/bin</directories>
<directories>/sbin</directories>

<!-- 3.1.6. Kernel Extensions -->
<directories>/System/Library/Extensions</directories>
<directories>/Library/Extensions</directories>

<!-- 3.1.7. SSH Configuration & Keys -->
<directories>/etc/ssh</directories>
<directories>/Users/*/.ssh</directories>

<!-- 3.1.8. Cron Jobs -->
<directories>/usr/lib/cron/tabs</directories>
<directories>/var/cron/tabs</directories>

<!-- 3.1.9. System & User Preferences -->
<directories>/Library/Preferences</directories>
<directories>/System/Library/Preferences</directories>
<directories>/Users/*/Library/Preferences</directories>

<!-- 3.1.10. Package Managers -->
<directories>/usr/local/bin</directories>
<directories>/opt/homebrew/bin</directories>

<!-- 3.1.11. Web Servers -->
<directories>/etc/apache2</directories>
<directories>/etc/nginx</directories>
<directories>/usr/local/etc/nginx</directories>

<!-- 3.1.12. Database Configurations -->
<directories>/usr/local/mysql</directories>
<directories>/usr/local/var/mysql</directories>

<!-- 3.1.13. Security Tools -->
<directories>/usr/local/bin/nmap</directories>
<directories>/usr/local/bin/wireshark</directories>

<!-- 3.1.14. System Libraries -->
<directories>/System/Library/Frameworks</directories>
<directories>/usr/lib</directories>

<!-- 3.1.15. Firewall Configuration -->
<directories>/etc/pf.conf</directories>

<!-- 3.1.16. Certificate Stores -->
<directories>/System/Library/Keychains</directories>
<directories>/Library/Keychains</directories>
```
3.2. Exclusion List (Ignored Paths)

To minimize noise, volatile and non-critical paths are excluded. These include caches, logs, temporary data, and user-specific transient files.
```
<!-- 3.2.1. Volatile Data -->
<ignore>/private/var/log</ignore>
<ignore>/private/var/tmp</ignore>
<ignore>/private/tmp</ignore>
<ignore>/System/Library/Caches</ignore>
<ignore>/Library/Caches</ignore>
<ignore>/Users/*/Library/Caches</ignore>
<ignore>/Users/*/Library/Logs</ignore>

<!-- 3.2.2. Dynamic State Files -->
<ignore>/private/var/run</ignore>
<ignore>/private/var/spool</ignore>
<ignore>/System/Library/Caches/com.apple.kext.caches</ignore>

<!-- 3.2.3. Regex Exclusions -->
<ignore type="sregex">\.log$|\.tmp$|\.cache$</ignore>
<ignore type="sregex">/Users/.*/\.Trash</ignore>
<ignore type="sregex">/Users/.*/\.DS_Store</ignore>
```
3.3. Sensitive Data Protection

Certain sensitive files are monitored for modifications, but the file diff content is suppressed to avoid exposing confidential data such as private keys and authentication secrets.
```
<nodiff>/etc/ssh/ssh_host_rsa_key</nodiff>
<nodiff>/etc/ssh/ssh_host_dsa_key</nodiff>
<nodiff>/etc/ssh/ssh_host_ecdsa_key</nodiff>
<nodiff>/etc/ssh/ssh_host_ed25519_key</nodiff>
<nodiff>/etc/master.passwd</nodiff>
<nodiff>/Users/*/Library/Keychains</nodiff>
<nodiff>/etc/ssl/private</nodiff>
```