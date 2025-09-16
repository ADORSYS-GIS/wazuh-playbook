### Overview
This document defines the configuration for the organization's File Integrity Monitoring (FIM) system on macOS endpoints. The policy is designed to detect and alert on unauthorized modifications to critical system files, directories, and configuration data, providing a core defense against malware, unauthorized changes, and security breaches.

### Scope
This configuration applies to all designated macOS systems enrolled in the corporate endpoint security management platform.

### Configuration Directives
3.1. Monitored Directories & Files
The following directories and files are monitored for changes to content, permissions, ownership, and other attributes.

```
<!-- 3.1.1. System Kernel & Core Services -->
<directories check_all="yes" report_changes="yes" realtime="yes">/System/Library/Extensions</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/System/Library/LaunchDaemons</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/System/Library/LaunchAgents</directories>
<directories check_all="yes" report_changes="yes">/System/Library/CoreServices</directories>
<directories check_all="yes" report_changes="yes">/System/Library/Frameworks</directories>

<!-- 3.1.2. Application & Service Persistence -->
<directories check_all="yes" report_changes="yes" realtime="yes">/Applications</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/Library/LaunchDaemons</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/Library/LaunchAgents</directories>
<directories check_all="yes" report_changes="yes">/Library/StartupItems</directories>
<directories check_all="yes" report_changes="yes">/Library/Application Support</directories>
<directories check_all="yes" report_changes="yes">/Library/Preferences</directories>

<!-- 3.1.3. User-Space Directories -->
<directories check_all="yes" report_changes="yes" realtime="yes">/Users/*/Library/LaunchAgents</directories>
<directories check_all="yes" report_changes="yes">/Users/*/Library/Application Support</directories>
<directories check_all="yes" report_changes="yes">/Users/*/Desktop</directories>
<directories check_all="yes" report_changes="yes">/Users/*/Downloads</directories>

<!-- 3.1.4. System Binaries & Configuration -->
<directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/bin</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/sbin</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/bin</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/sbin</directories>

<!-- 3.1.5. Security-Critical Assets -->
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/ssh</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/ssl</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/local/bin</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/local/sbin</directories>

<!-- 3.1.6. Web Services (Conditional) -->
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/local/apache2</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/usr/local/nginx</directories>

<!-- 3.1.7. Critical Specific Files -->
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/hosts</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/passwd</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/group</directories>
<directories check_all="yes" report_changes="yes" realtime="yes">/private/etc/sudoers</directories>
```

### 3.2. Exclusion List (Ignored Paths)
The following paths are excluded from monitoring to minimize noise from volatile, temporary, or non-essential data.

```
<!-- 3.2.1. System Volatile Data -->
<ignore>/private/var/log</ignore>
<ignore>/private/var/tmp</ignore>
<ignore>/private/tmp</ignore>
<ignore>/System/Library/Caches</ignore>
<ignore>/Library/Caches</ignore>
<ignore>/Users/*/Library/Caches</ignore>
<ignore>/Users/*/Library/Logs</ignore>

<!-- 3.2.2. Application & System Databases -->
<ignore>/private/var/db/dyld</ignore>
<ignore>/private/var/db/receipts</ignore>
<ignore>/private/var/folders</ignore>
<ignore>/Users/*/Library/Safari/Databases</ignore>
<ignore>/Users/*/Library/Mail/V*</ignore>

<!-- 3.2.3. Dynamic State Files -->
<ignore>/private/etc/localtime</ignore>
<ignore>/private/var/run</ignore>
<ignore>/private/var/spool</ignore>
<ignore>/System/Library/Caches/com.apple.kext.caches</ignore>

<!-- 3.2.4. Pattern Exclusions (Regex) -->
<ignore type="sregex">\.log$|\.tmp$|\.cache$</ignore>
<ignore type="sregex">/Users/.*/\.Trash</ignore>
<ignore type="sregex">/Users/.*/\.DS_Store</ignore>
<ignore type="sregex">/private/var/vm/swap</ignore>
```

### 3.3. Sensitive Data Protection
Changes to the following files are alerted on, but the actual content (diff) is suppressed to prevent exposure of sensitive information.

```
<nodiff>/private/etc/ssh/ssh_host_rsa_key</nodiff>
<nodiff>/private/etc/ssh/ssh_host_dsa_key</nodiff>
<nodiff>/private/etc/ssh/ssh_host_ecdsa_key</nodiff>
<nodiff>/private/etc/ssh/ssh_host_ed25519_key</nodiff>
<nodiff>/private/etc/master.passwd</nodiff>
<nodiff>/Users/*/Library/Keychains</nodiff>
<nodiff>/private/etc/ssl/private</nodiff>
```
