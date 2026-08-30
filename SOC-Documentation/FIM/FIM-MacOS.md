### Overview

This document defines the configuration for the organization's File Integrity Monitoring (FIM) system on macOS endpoints. The policy is designed to detect and alert on unauthorized modifications to critical system files, directories, and configuration data, providing a core defense against malware, unauthorized changes, and security breaches.

### Scope

This configuration applies to all designated macOS systems enrolled in the corporate endpoint security management platform.

### Configuration Directives

3.1. Monitored Directories & Files
 The following directories and files are monitored for changes to content, permissions, ownership, and other attributes.

 ```
  <!-- MacOS Endpoints configuration -->
  <agent_config os="Darwin">
    <!-- File Integrity Monitoring (FIM) -->
    <syscheck>
      <file_limit>
        <enabled>no</enabled>
      </file_limit>
      <disabled>no</disabled>
      <frequency>14400</frequency>
      <!-- 4 hours -->
      <directories>/etc/master.passwd</directories>
      <directories>/usr/bin</directories>
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
      <directories>/Library/Preferences</directories>
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
      <directories>/private/etc/ssh</directories>This matches only paths that start with /tmp/,
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
      <!-- Files/directories to ignore -->
      <ignore>/Library</ignore>
      <ignore>/Users</ignore>
      <ignore>/System/Volumes/Preboot/</ignore>
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
    </syscheck>
    <!-- Log collection -->
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/system.log</location>
    </localfile>
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/auth.log</location>
    </localfile>
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/install.log</location>
    </localfile>
  </agent_config>


NOTE: For the full list of Syscheck (FIM) configuration options and advanced usage, check out [here](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html) 
