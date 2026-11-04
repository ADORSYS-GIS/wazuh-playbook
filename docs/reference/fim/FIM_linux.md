### Overview

This document defines the configuration for the organization's File Integrity Monitoring (FIM) system on Linux endpoints. The policy is designed to detect and alert on unauthorized modifications to critical system files, directories, and configuration data, providing a core defense against malware, unauthorized changes, and security breaches.

### Scope

This configuration applies to all designated Linux systems enrolled in the corporate endpoint security management platform.

### Configuration Directives

3.1. Monitored Directories & Files
The following directories and files are monitored for changes to content, permissions, ownership, and other attributes:

```
  <!-- Linux Endpoints configuration -->
  <agent_config os="Linux">
    <!-- File Integrity Monitoring (FIM) -->
    <syscheck>
      <file_limit>
        <enabled>no</enabled>
      </file_limit>
      <disabled>no</disabled>
      <frequency>60</frequency>
      <!-- 4 hours -->
      <directories>/etc/passwd,/etc/shadow,/etc/group</directories>
      <directories>/etc/ssh/sshd_config,~/.ssh/authorized_keys</directories>
      <directories>/boot/grub/grub.cfg</directories>
      <directories>/bin,/sbin,/usr/bin,/usr/local/bin</directories>
      <directories>/etc/crontab,/var/spool/cron</directories>
      <directories>/tmp,/var/tmp</directories>
      <directories>/root</directories>
      <!-- Files/directories to ignore -->
      <ignore>/home</ignore>
      <!-- Directories to monitor -->
      <directories>/etc</directories>
      <directories>/bin</directories>
      <directories>/sbin</directories>
      <directories>/usr/bin</directories>
      <directories>/usr/sbin</directories>
      <directories>/var/www</directories>
      <directories>/opt/apps</directories>
      <directories>/boot</directories>
      <directories>/etc/ssh</directories>
      <directories>/etc/systemd/system</directories>
      <directories>/lib/systemd/system</directories>
      <directories>/etc/cron.d</directories>
      <directories>/etc/cron.daily</directories>
      <directories>/etc/cron.weekly</directories>
      <directories>/etc/cron.monthly</directories>
      <directories>/var/spool/cron</directories>
      <directories>/home/*/.ssh/authorized_keys</directories>
      <directories>/home/*/.bashrc</directories>
      <directories>/home/*/.profile</directories>
      <directories>/home/*/.config/autostart</directories>
      <directories>/etc</directories>
      <directories>/var/www</directories>
      <directories>/opt/apps</directories>
      <!-- Excludes -->
      <ignore>/var/run</ignore>
      <ignore>/var/lock</ignore>
      <ignore>/tmp</ignore>
      <ignore>/dev</ignore>
      <ignore>/proc</ignore>
      <ignore>/sys</ignore>
      <ignore>/var/log/wtmp</ignore>
      <ignore>/var/log/btmp</ignore>
      <ignore>/var/log/lastlog</ignore>
      <ignore>/etc/mtab</ignore>
    </syscheck>
    <!-- Log collection -->
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/auth.log</location>
    </localfile>
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/syslog</location>
    </localfile>
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/secure</location>
    </localfile>
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/suricata/eve.json</location>
    </localfile>
  </agent_config>

```
