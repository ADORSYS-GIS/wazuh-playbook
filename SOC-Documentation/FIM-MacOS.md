### Overview
This document defines the configuration for the organization's File Integrity Monitoring (FIM) system on macOS endpoints. The policy is designed to detect and alert on unauthorized modifications to critical system files, directories, and configuration data, providing a core defense against malware, unauthorized changes, and security breaches.

### Scope
This configuration applies to all designated macOS systems enrolled in the corporate endpoint security management platform.

### Configuration Directives
3.1. Monitored Directories & Files
The following directories and files are monitored for changes to content, permissions, ownership, and other attributes.

```
<!-- 3.1.1. System Kernel & Core Services -->
<directories>/System/Library/Extensions</directories>
      <directories>/System/Library/LaunchDaemons</directories>
      <directories>/System/Library/LaunchAgents</directories>
      <directories>/System/Library/CoreServices</directories>
      <directories>/System/Library/Frameworks</directories>

<!-- 3.1.2. Application & Service Persistence -->
<directories>/Applications</directories>
      <directories>/Library/LaunchDaemons</directories>
      <directories>/Library/LaunchAgents</directories>
      <directories>/Library/StartupItems</directories>
      <directories>/Library/Application Support</directories>
      <directories>/Library/Preferences</directories

<!-- 3.1.3. User-Space Directories -->
 <directories>/Users/*/Library/LaunchAgents</directories>
 <directories>/Users/*/Library/Application Support</directories>
      
<!-- 3.1.4. System Binaries & Configuration -->
<directories>/etc</directories>
      <directories>/usr/bin</directories>
      <directories>/usr/sbin</directories>
      <directories>/bin</directories>
      <directories>/sbin</directories>

<!-- 3.1.5. Security-Critical Assets -->
<directories>/private/etc/ssh</directories>
      <directories>/private/etc/ssl</directories>
      <directories>/usr/local/bin</directories>
      <directories>/usr/local/sbin</directories>

<!-- 3.1.6. Web Services (Conditional) -->
<directories>/usr/local/apache2</directories>
      <directories>/usr/local/nginx</directories>

<!-- 3.1.7. Critical Specific Files -->
   <directories>/private/etc/hosts</directories>
      <directories>/private/etc/passwd</directories>
      <directories>/private/etc/group</directories>
      <directories>/private/etc/sudoers</directories>
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
###Wazuh Syscheck (FIM) Attributes
     The attributes below define what to monitor, how to monitor it, and which changes should trigger alerts. Understanding these settings is key to building an effective FIM policy that balances security coverage with system performance.
| Attribute             | What it does |
|------------------------|--------------|
| `<directories>`        | Defines which directories Wazuh should monitor for file changes. |
| `check_all`            | Enables all checks (size, perms, owner, group, hashes, inode, etc.). |
| `check_sum`            | Monitors file checksums (hashes like md5, sha1, sha256) to detect content changes. |
| `check_size`           | Monitors file size changes. |
| `check_perm`           | Monitors file permission changes. |
| `check_owner`          | Monitors changes in file ownership. |
| `check_group`          | Monitors group ownership changes. |
| `check_inode`          | Monitors inode changes (file metadata). |
| `<frequency>`          | Defines how often (in seconds) Wazuh performs a periodic scan. |
| `<scan_time>`          | Runs a scan at a specific time of day. |
| `<scan_day>`           | Runs a scan on specific day(s) of the week. |
| `<ignore>`             | Excludes certain files or directories from monitoring. |
| `<nodiff>`             | Prevents storing copies of modified files (useful for sensitive data). |

NOTE: For the full list of Syscheck (FIM) configuration options and advanced usage, see the [https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html]