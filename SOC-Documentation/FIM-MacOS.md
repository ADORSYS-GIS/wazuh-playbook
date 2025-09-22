### Overview

This document defines the configuration for the organization's File Integrity Monitoring (FIM) system on macOS endpoints. The policy is designed to detect and alert on unauthorized modifications to critical system files, directories, and configuration data, providing a core defense against malware, unauthorized changes, and security breaches.

### Scope

This configuration applies to all designated macOS systems enrolled in the corporate endpoint security management platform.

### Configuration Directives

3.1. Monitored Directories & Files
 The following directories and files are monitored for changes to content, permissions, ownership, and other attributes.

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


 ### Wazuh Syscheck (FIM) Attributes
The attributes below define what to monitor, how to monitor it, and which changes should trigger alerts. Understanding these settings is key to building an effective FIM policy that balances security coverage with system performance.
| Attribute        | What it does                                                                 |
|-----------------|----------------------------------------------------------------------------|
| `<directories>`  | Defines which directories Wazuh should monitor for file changes.           |
| `check_all`      | Enables all checks (size, perms, owner, group, hashes, inode, etc.).       |
| `check_sum`      | Monitors file checksums (hashes like md5, sha1, sha256) to detect content changes. |
| `check_size`     | Monitors file size changes.                                                |
| `check_perm`     | Monitors file permission changes.                                          |
| `check_owner`    | Monitors changes in file ownership.                                        |
| `check_group`    | Monitors group ownership changes.                                          |
| `check_inode`    | Monitors inode changes (file metadata).                                    |
| `<frequency>`    | Defines how often (in seconds) Wazuh performs a periodic scan.            |
| `<scan_time>`    | Runs a scan at a specific time of day.                                     |
| `<scan_day>`     | Runs a scan_


NOTE: For the full list of Syscheck (FIM) configuration options and advanced usage, check out [here](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html) 
