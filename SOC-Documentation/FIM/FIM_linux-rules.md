### Linux Security Monitoring Rules for OSSEC/Wazuh

This document outlines a comprehensive set of security monitoring rules for Linux environments, specifically designed for use with OSSEC/Wazuh.
It aims to provide advanced threat detection capabilities while minimizing false positives through intelligent noise reduction.

### Coverage Areas

* **Critical System Events**: Monitoring for kernel panics, fatal errors, and core system crashes.

* **File Integrity Monitoring (FIM)**: Watching for unauthorized changes to critical system files (e.g., /etc/passwd, /etc/shadow, /etc/sudoers), binaries (/bin, /usr/bin, /sbin, /usr/sbin), and service configurations (/etc/systemd/*, /etc/init.d/*).

* **Root Access Monitoring**: Logging and alerting on the use of the root account and su/sudo activity to track privileged access.

* **Persistence Mechanisms**: Monitoring for suspicious additions or modifications in crontabs, systemd units, and user-level autostart directories.

* **SSH Security**: Detecting modifications to SSH configurations (/etc/ssh/sshd_config) and monitoring changes to authorized keys.

* **Privilege Escalation**: Detecting changes to the sudoers file, privilege escalation attempts, or abnormal setuid/setgid binary modifications.

* **Log Tampering**: Alerting on attempts to clear, delete, or manipulate logs (/var/log/*) to cover tracks.

* **Network & Service Monitoring**: Watching for unexpected modifications to firewall configurations (iptables/nftables), network services, and listening ports.

### Key Features

- Intelligent noise reduction to filter out routine administrative and system activities.

- Time-based rules to reduce alerts during planned maintenance windows.

- Severity-level-based alerting (levels 0–15).

**Ruleset(xml)
```


<group name="local,linux,ssh">
    <rule id="700001" level="7">
        <if_group>syslog</if_group>
        <match>Failed password</match>
        <description>Failed SSH login attempt detected</description>
    </rule>
    
    <rule id="700002" level="10" frequency="5" timeframe="300">
        <if_matched_sid>700001</if_matched_sid>
        <description>Possible SSH brute force attack</description>
    </rule>
    
    <rule id="700003" level="0">
        <if_matched_sid>700001</if_matched_sid>
        <srcip>192.168.1.0/24</srcip>
        <description>Ignore failed SSH login from trusted network</description>
    </rule>
    
    <rule id="700004" level="0">
        <if_matched_sid>700001</if_matched_sid>
        <match>testuser|backupuser</match>
        <description>Ignore failed SSH login for specific accounts</description>
    </rule>
    
    <rule id="700005" level="12">
        <if_group>syslog</if_group>
        <match>sshd.*Failed password for root</match>
        <description>Failed SSH login attempt for root user</description>
    </rule>
    
    <rule id="700006" level="10" frequency="5" timeframe="300">
        <if_matched_sid>700001</if_matched_sid>
        <description>Possible SSH brute force attack</description>
    </rule>
    
    <rule id="700007" level="0">
        <if_matched_sid>700006</if_matched_sid>
        <srcip>192.168.1.0/24</srcip>
        <description>Ignore SSH brute force alerts from trusted network</description>
    </rule>
    
    <rule id="700008" level="0">
        <if_matched_sid>700006</if_matched_sid>
        <match>testuser|backupuser</match>
        <description>Ignore SSH brute force alerts for specific accounts</description>
    </rule>
    
    <rule id="700009" level="12">
        <if_matched_sid>700006</if_matched_sid>
        <match>root</match>
        <description>SSH brute force attempt targeting root user</description>
    </rule>
    
    <rule id="700011" level="0">
        <if_group>syslog</if_group>
        <match>sudo:</match>
        <description>Unauthorized sudo command execution</description>
    </rule>
    
    <rule id="700012" level="0">
        <if_matched_sid>700011</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore sudo usage from trusted admin accounts</description>
    </rule>
    
    <rule id="700013" level="0">
        <if_matched_sid>700011</if_matched_sid>
        <match>sudo ls|sudo cat</match>
        <description>Ignore benign sudo commands</description>
    </rule>
    
    <rule id="700014" level="12">
        <if_matched_sid>700011</if_matched_sid>
        <match>sudo vi /etc/sudoers|sudo useradd|sudo passwd</match>
        <description>Sensitive sudo command execution detected</description>
    </rule>
    
    <rule id="700016" level="12">
        <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
        <description>Critical system file modification detected</description>
    </rule>
    
    <rule id="700017" level="0">
        <if_matched_sid>700016</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore critical file changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700019" level="12">
        <if_matched_sid>700016</if_matched_sid>
        <match>deleted</match>
        <description>Critical system file deletion detected</description>
    </rule>
    
    <rule id="700020" level="0">
        <if_matched_sid>700016</if_matched_sid>
        <match>apt|yum|dnf</match>
        <description>Ignore critical file changes from package manager updates</description>
    </rule>
    
    <rule id="700021" level="12">
        <if_group>syslog</if_group>
        <match>kernel panic</match>
        <description>Kernel panic or critical error detected</description>
    </rule>
    
    <rule id="700022" level="12">
        <if_matched_sid>700021</if_matched_sid>
        <match>kernel</match>
        <description>Kernel panic or Oops from kernel facility only</description>
    </rule>
    
    <rule id="700023" level="0">
        <if_matched_sid>700021</if_matched_sid>
        <match>Oops.*known_issue_module</match>
        <description>Ignore kernel Oops from known benign module</description>
    </rule>
    
    <rule id="700025" level="15">
        <if_matched_sid>700021</if_matched_sid>
        <match>hardware error|Machine check</match>
        <description>Critical hardware-related kernel panic detected</description>
    </rule>
    
    <rule id="700026" level="7">
        <if_group>syslog</if_group>
        <match>systemd.*(started|stopped)</match>
        <description>Unexpected service start/stop detected</description>
    </rule>
    
    <rule id="700027" level="0">
        <if_matched_sid>700026</if_matched_sid>
        <match>systemd.*(started|stopped).*cron|systemd.*(started|stopped).*rsyslog</match>
        <description>Ignore start/stop events for routine services</description>
    </rule>
    
    <rule id="700029" level="10">
        <if_matched_sid>700026</if_matched_sid>
        <match>systemd.*(started|stopped).*sshd|systemd.*(started|stopped).*iptables</match>
        <description>Critical service start/stop detected</description>
    </rule>
    
    <rule id="700030" level="9" frequency="3" timeframe="300">
        <if_matched_sid>700026</if_matched_sid>
        <description>Service start/stop occurring multiple times in short timeframe</description>
    </rule>
    
    <rule id="700031" level="9">
        <if_group>syslog</if_group>
        <match>Accepted password for root</match>
        <description>Root login detected</description>
    </rule>
    
    <rule id="700032" level="0">
        <if_matched_sid>700031</if_matched_sid>
        <srcip>192.168.1.0/24</srcip>
        <description>Ignore root logins from trusted network</description>
    </rule>
    
    <rule id="700033" level="0">
        <if_matched_sid>700031</if_matched_sid>
        <user>automation|backupadmin</user>
        <description>Ignore root logins from automation or backup accounts</description>
    </rule>
    
    <rule id="700034" level="12">
        <if_matched_sid>700031</if_matched_sid>
        <srcip>!192.168.1.0/24</srcip>
        <description>Root login from external network detected</description>
    </rule>
    
    <rule id="700035" level="3">
        <if_sid>5401</if_sid>
        <match>sudo: pam_unix(sudo:session): session opened for user root</match>
        <description>Successful sudo login to root (level 0)</description>
        <group>sudo,authentication_success,privilege_escalation</group>
    </rule>
    
    <rule id="700036" level="4">
        <if_sid>5401</if_sid>
        <regex>sudo: \S+ : TTY=\S+ ; PWD=\S+ ; USER=root ; COMMAND=</regex>
        <description>Successful sudo command execution as root (level 0)</description>
        <group>sudo,authentication_success,privilege_escalation</group>
    </rule>
    
    <!-- Critical User Account Files -->
    <rule id="700037" level="12">
        <match>/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow</match>
        <description>Critical user account file modification detected</description>
    </rule>
    
    <rule id="700038" level="0">
        <if_matched_sid>700037</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore critical account file changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700039" level="0">
        <if_matched_sid>700037</if_matched_sid>
        <match>useradd|usermod|groupadd|groupdel|apt|yum|dnf</match>
        <description>Ignore critical account file changes from trusted programs</description>
    </rule>
    
    <rule id="700040" level="12">
        <if_matched_sid>700037</if_matched_sid>
        <match>!useradd|!usermod|!groupadd|!groupdel|!apt|!yum|!dnf</match>
        <description>Unexpected critical account file modification detected</description>
    </rule>
    
    <!-- SSH Configuration -->
    <rule id="700041" level="10">
        <match>/etc/ssh/sshd_config</match>
        <description>SSH configuration file modification detected</description>
    </rule>
    
    <rule id="700042" level="0">
        <if_matched_sid>700041</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore SSH configuration changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700043" level="0">
        <if_matched_sid>700041</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore SSH configuration changes from trusted automation tools</description>
    </rule>
    
    <rule id="700044" level="12">
        <if_matched_sid>700041</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected SSH configuration file modification detected</description>
    </rule>
    
    <!-- Sudoers File -->
    <rule id="700045" level="12">
        <match>/etc/sudoers</match>
        <description>Sudoers file modification detected</description>
    </rule>
    
    <rule id="700046" level="0">
        <if_matched_sid>700045</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore Sudoers file changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700047" level="0">
        <if_matched_sid>700045</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore Sudoers file changes from trusted automation tools</description>
    </rule>
    
    <rule id="700048" level="12">
        <if_matched_sid>700045</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected Sudoers file modification detected</description>
    </rule>
    
    <!-- System Startup Scripts -->
    <rule id="700049" level="9">
        <match>/etc/rc.local|/etc/init.d/anacron/</match>
        <description>System startup script modification detected</description>
    </rule>
    
    <rule id="700050" level="0">
        <if_matched_sid>700049</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore startup script changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700051" level="0">
        <if_matched_sid>700049</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore startup script changes from trusted automation tools</description>
    </rule>
    
    <rule id="700052" level="12">
        <if_matched_sid>700049</if_matched_sid>
        <match>!ansible|!puppet|!chef|!cron</match>
        <description>Unexpected system startup script modification detected</description>
    </rule>
    
    <!-- Filesystem Table -->
    <rule id="700053" level="10">
        <match>/etc/fstab</match>
        <description>Filesystem table modification detected</description>
    </rule>
    
    <rule id="700054" level="0">
        <if_matched_sid>700053</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore filesystem table changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700055" level="0">
        <if_matched_sid>700053</if_matched_sid>
        <match>mount|umount|ansible|puppet|chef</match>
        <description>Ignore filesystem table changes from trusted programs</description>
    </rule>
    
    <rule id="700056" level="12">
        <if_matched_sid>700053</if_matched_sid>
        <match>!mount|!umount|!ansible|!puppet|!chef</match>
        <description>Unexpected filesystem table modification detected</description>
    </rule>
    
    <!-- Cron Jobs -->
    <rule id="700057" level="9">
        <match>/etc/crontab|/etc/cron.d/|/etc/cron.daily/|/etc/cron.weekly/</match>
        <description>Cron job modification detected</description>
    </rule>
    
    <rule id="700058" level="0">
        <if_matched_sid>700041</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore cron job changes from trusted automation tools</description>
    </rule>
    
    <rule id="700059" level="12">
        <if_matched_sid>700041</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected cron job modification detected</description>
    </rule>
    
    <rule id="700060" level="0">
        <if_matched_sid>700041</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore cron job changes from trusted admin accounts</description>
    </rule>
    
    <!-- Network Configuration -->
    <rule id="700061" level="9">
        <match>/etc/network/interfaces|/etc/sysconfig/network-scripts/</match>
        <description>Network configuration file modification detected</description>
    </rule>
    
    <rule id="700062" level="0">
        <if_matched_sid>700061</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore network configuration changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700063" level="0">
        <if_matched_sid>700061</if_matched_sid>
        <match>ansible|puppet|chef|nmcli|ifconfig</match>
        <description>Ignore network configuration changes from trusted programs</description>
    </rule>
    
    <rule id="700064" level="12">
        <if_matched_sid>700061</if_matched_sid>
        <match>!ansible|!puppet|!chef|!nmcli|!ifconfig</match>
        <description>Unexpected network configuration file modification detected</description>
    </rule>
</group>

<group name="local,linux,security">
    <!-- Detection of New User Creation -->
    <rule id="700065" level="10">
        <if_group>syslog</if_group>
        <match>useradd|adduser</match>
        <description>New user account created</description>
    </rule>
    
    <rule id="700066" level="0">
        <if_matched_sid>700065</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore new user creation from trusted admin accounts</description>
    </rule>
    
    <rule id="700067" level="0">
        <if_matched_sid>700065</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore new user creation from trusted automation tools</description>
    </rule>
    
    <rule id="700068" level="12">
        <if_matched_sid>700065</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected new user account creation detected</description>
    </rule>
    
    <!-- Detection of User Deletion -->
    <rule id="700069" level="10">
        <if_group>syslog</if_group>
        <match>userdel</match>
        <description>User account deleted</description>
    </rule>
    
    <rule id="700070" level="0">
        <if_matched_sid>700069</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore user deletion from trusted admin accounts</description>
    </rule>
    
    <rule id="700071" level="0">
        <if_matched_sid>700069</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore user deletion from trusted automation tools</description>
    </rule>
    
    <rule id="700072" level="12">
        <if_matched_sid>700069</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected user account deletion detected</description>
    </rule>
    
    <!-- Detection of Group Changes -->
    <rule id="700073" level="9">
        <if_group>syslog</if_group>
        <match>groupadd|groupdel|gpasswd</match>
        <description>User group modification detected</description>
    </rule>
    
    <rule id="700074" level="0">
        <if_matched_sid>700073</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore group changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700075" level="0">
        <if_matched_sid>700073</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore group changes from trusted automation tools</description>
    </rule>
    
    <rule id="700076" level="12">
        <if_matched_sid>700073</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected user group modification detected</description>
    </rule>
    
    <!-- Detection of Package Installation -->
    <rule id="700077" level="8">
        <if_group>syslog</if_group>
        <match>apt-get install|yum install|dnf install</match>
        <description>Software package installation detected</description>
    </rule>
    
    <rule id="700078" level="0">
        <if_matched_sid>700077</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore package installations from trusted admin accounts</description>
    </rule>
    
    <rule id="700079" level="0">
        <if_matched_sid>700077</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore package installations from trusted automation tools</description>
    </rule>
    
    <rule id="700080" level="12">
        <if_matched_sid>700077</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected software package installation detected</description>
    </rule>
    
    <!-- Detection of Package Removal -->
    <rule id="700081" level="8">
        <if_group>syslog</if_group>
        <match>apt-get remove|yum remove|dnf remove</match>
        <description>Software package removal detected</description>
    </rule>
    
    <rule id="700082" level="0">
        <if_matched_sid>700081</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore package removals from trusted admin accounts</description>
    </rule>
    
    <rule id="700083" level="0">
        <if_matched_sid>700081</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore package removals from trusted automation tools</description>
    </rule>
    
    <rule id="700084" level="12">
        <if_matched_sid>700081</if_matched_sid>
        <match>!ansible|!puppet|!chef|!kube-proxy</match>
        <description>Unexpected software package removal detected</description>
    </rule>
    
    <!-- Detection of Firewall Changes -->
    <rule id="700085" level="10">
        <if_group>syslog</if_group>
        <match>iptables|firewalld|ufw|!k3s|!kube-proxy</match>
        <description>Firewall configuration change detected</description>
    </rule>
    
    <rule id="700086" level="0">
        <if_matched_sid>700085</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore firewall changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700087" level="0">
        <if_matched_sid>700085</if_matched_sid>
        <match>ansible|puppet|chef|k3s|kube-proxy</match>
        <description>Ignore firewall changes from trusted automation tools</description>
    </rule>
    
    <!-- Detection of Suspicious Network Connections -->
    <!--
    <rule id="700088" level="12">
        <if_group>syslog</if_group>
        <match>connect from|connection attempt</match>
        <description>Suspicious inbound network connection detected</description>
    </rule>
    -->
    
    <rule id="700089" level="0">
        <if_matched_sid>700088</if_matched_sid>
        <match>port 80|port 443</match>
        <description>Ignore inbound connections to allowed services</description>
    </rule>
    
    <!-- Detection of Privilege Escalation Commands -->
    <rule id="700090" level="12">
        <if_group>syslog</if_group>
        <match>sudo su|sudo -i</match>
        <description>Privilege escalation attempt detected</description>
    </rule>
    
    <rule id="700091" level="0">
        <if_matched_sid>700090</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore privilege escalation attempts from trusted admin accounts</description>
    </rule>
    
    <rule id="700092" level="0">
        <if_matched_sid>700090</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore privilege escalation attempts from trusted automation tools</description>
    </rule>
    
    <rule id="700093" level="12">
        <if_matched_sid>700090</if_matched_sid>
        <user>!adminuser|!sysadmin</user>
        <description>Unexpected privilege escalation attempt detected</description>
    </rule>
    
    <!-- Detection of Changes to /etc/hosts -->
    <rule id="700094" level="9">
        <match>/etc/hosts</match>
        <description>Hosts file modification detected</description>
    </rule>
    
    <rule id="700095" level="0">
        <if_matched_sid>700094</if_matched_sid>
        <user>adminuser|sysadmin</user>
        <description>Ignore hosts file changes from trusted admin accounts</description>
    </rule>
    
    <rule id="700096" level="0">
        <if_matched_sid>700094</if_matched_sid>
        <match>ansible|puppet|chef</match>
        <description>Ignore hosts file changes from trusted automation tools</description>
    </rule>
    
    <rule id="700097" level="12">
        <if_matched_sid>700094</if_matched_sid>
        <match>!ansible|!puppet|!chef</match>
        <description>Unexpected hosts file modification detected</description>
    </rule>
</group>

									
		
```