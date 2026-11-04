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
	<rule id="100001" level="7">	
		<if_group >syslog</if_group>
		<match >Failed password</match>
		<description >Failed SSH login attempt detected</description>
	</rule>	
	<rule id="100002" level="10" frequency="5" timeframe="300">	
		<if_matched_sid>100001</if_matched_sid>
		<description >Possible SSH brute force attack</description>
	</rule>	
	<rule id="100003" level="0">	
		<if_matched_sid >100001</if_matched_sid>
		<srcip >192.168.1.0/24</srcip>
		<description >Ignore failed SSH login from trusted network</description>
	</rule>	
	<rule id="100004" level="0">	
		<if_matched_sid >100001</if_matched_sid>
		<match >testuser|backupuser</match>
		<description >Ignore failed SSH login for specific accounts</description>
	</rule>	
	<rule id="100005" level="12">	
		<if_group >syslog</if_group>
		<match >sshd.*Failed password for root</match>
		<description >Failed SSH login attempt for root user</description>
	</rule>	
	<rule id="100006" level="10" frequency="5" timeframe="300">	
		<if_matched_sid >100001</if_matched_sid>
		<description >Possible SSH brute force attack</description>
	</rule>	
	<rule id="100007" level="0">	
		<if_matched_sid >100006</if_matched_sid>
		<srcip >192.168.1.0/24</srcip>
		<description >Ignore SSH brute force alerts from trusted network</description>
	</rule>	
	<rule id="100008" level="0">	
		<if_matched_sid >100006</if_matched_sid>
		<match >testuser|backupuser</match>
		<description >Ignore SSH brute force alerts for specific accounts</description>
	</rule>	
	<rule id="100009" level="12">	
		<if_matched_sid >100006</if_matched_sid>
		<match >root</match>
		<description >SSH brute force attempt targeting root user</description>
	</rule>	
	<rule id="100011" level="8">	
		<if_group >syslog</if_group>
		<match >sudo:</match>
		<description >Unauthorized sudo command execution</description>
	</rule>	
	<rule id="100012" level="0">	
		<if_matched_sid >100011</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore sudo usage from trusted admin accounts</description>
	</rule>	
	<rule id="100013" level="0">	
		<if_matched_sid >100011</if_matched_sid>
		<match >sudo ls|sudo cat</match>
		<description >Ignore benign sudo commands</description>
	</rule>	
	<rule id="100014" level="12">	
		<if_matched_sid >100011</if_matched_sid>
		<match >sudo vi /etc/sudoers|sudo useradd|sudo passwd</match>
		<description >Sensitive sudo command execution detected</description>
	</rule>	
	<rule id="100016" level="12">	
		<match >/etc/passwd|/etc/shadow|/etc/sudoers</match>
		<description >Critical system file modification detected</description>
	</rule>	
	<rule id="100017" level="0">	
		<if_matched_sid >100016</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore critical file changes from trusted admin accounts</description>
	</rule>	
	<rule id="100019" level="12">	
		<if_matched_sid >100016</if_matched_sid>
		<match >deleted</match>
		<description >Critical system file deletion detected</description>
	</rule>	
	<rule id="100020" level="0">	
		<if_matched_sid >100016</if_matched_sid>
		<match >apt|yum|dnf</match>
		<description >Ignore critical file changes from package manager updates</description>
	</rule>	
	<rule id="100021" level="12">	
		<if_group >syslog</if_group>
		<match >kernel panic|Oops</match>
		<description >Kernel panic or critical error detected</description>
	</rule>	
	<rule id="100022" level="12">	
		<if_matched_sid >100021</if_matched_sid>
		<match >kernel</match>
		<description >Kernel panic or Oops from kernel facility only</description>
	</rule>	
	<rule id="100023" level="0">	
		<if_matched_sid >100021</if_matched_sid>
		<match >Oops.*known_issue_module</match>
		<description >Ignore kernel Oops from known benign module</description>
	</rule>	
	<rule id="100025" level="15">	
		<if_matched_sid >100021</if_matched_sid>
		<match >hardware error|Machine check</match>
		<description >Critical hardware-related kernel panic detected</description>
	</rule>	
	<rule id="100026" level="7">	
		<if_group >syslog</if_group>
		<match >systemd.*(started|stopped)</match>
		<description >Unexpected service start/stop detected</description>
	</rule>	
	<rule id="100027" level="0">	
		<if_matched_sid >100026</if_matched_sid>
		<match >systemd.*(started|stopped).*cron|systemd.*(started|stopped).*rsyslog</match>
		<description >Ignore start/stop events for routine services</description>
	</rule>	
    	<rule id="100029" level="10">
    	<if_matched_sid >100026</if_matched_sid>
    	<match >systemd.*(started|stopped).*sshd|systemd.*(started|stopped).*iptables</match>
    	<description >Critical service start/stop detected</description>
    </rule>
    <rule id="100030" level="9" frequency="3" timeframe="300">
    	<if_matched_sid >100026</if_matched_sid>
    	<description >Service start/stop occurring multiple times in short timeframe</description>
    </rule>
    <rule id="100007" level="9">
    	<if_group >syslog</if_group>
    	<match >Accepted password for root</match>
    	<description >Root login detected</description>
    </rule>
    <rule id="100031" level="0">
    	<if_matched_sid >100007</if_matched_sid>
    	<srcip >192.168.1.0/24</srcip>
    	<description >Ignore root logins from trusted network</description>
    </rule>
    <rule id="100032" level="0">
    	<if_matched_sid >100007</if_matched_sid>
    	<user >automation|backupadmin</user>
    	<description >Ignore root logins from automation or backup accounts</description>
    </rule>
    <rule id="100034" level="12">
    	<if_matched_sid >100007</if_matched_sid>
    	<srcip >!192.168.1.0/24</srcip>
    	<description >Root login from external network detected</description>
    </rule>
    Critical User Account Files 
    <rule id="200001" level="12">
    	<match >/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow</match>
    	<description >Critical user account file modification detected</description>
    </rule>
    <rule id="200002" level="0">
    	<if_matched_sid >200001</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore critical account file changes from trusted admin                                                                           
        accounts</description>
    </rule>
    <rule id="200004" level="0">
    	<if_matched_sid >200001</if_matched_sid>
    	<match >useradd|usermod|groupadd|groupdel|apt|yum|dnf</match>
    	<description >Ignore critical account file changes from trusted programs</description>
    </rule>
    <rule id="200005" level="12">
    	<if_matched_sid >200001</if_matched_sid>
    	<match >!useradd|!usermod|!groupadd|!groupdel|!apt|!yum|!dnf</match>
    	<description >Unexpected critical account file modification detected</description>
    </rule>
                     SSH Configuration 
                    
    <rule id="200006" level="10">
    	<match >/etc/ssh/sshd_config</match>
    	<description >SSH configuration file modification detected</description>
    </rule>
    <rule id="200007" level="0">
    	<if_matched_sid >200006</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore SSH configuration changes from trusted admin                                                                               
        accounts</description>
    </rule>
    <rule id="200009" level="0">
    	<if_matched_sid >200006</if_matched_sid>
    	<match >ansible|puppet|chef</match>
    	<description >Ignore SSH configuration changes from trusted automation                                                                          
        tools</description>
    </rule>
    <rule id="200010" level="12">
    	<if_matched_sid >200006</if_matched_sid>
    	<match >!ansible|!puppet|!chef</match>
    	<description >Unexpected SSH configuration file modification detected</description>
    </rule>
        Sudoers File 
    <rule id="200011" level="12">
    	<match >/etc/sudoers</match>
    	<description >Sudoers file modification detected</description>
    </rule>
    <rule id="200012" level="0">
    	<if_matched_sid >200011</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore Sudoers file changes from trusted admin accounts</description>
    </rule>
    <rule id="200014" level="0">
    	<if_matched_sid >200011</if_matched_sid>
    	<match >ansible|puppet|chef</match>
    	<description >Ignore Sudoers file changes from trusted automation tools</description>
    </rule>
    <rule id="200015" level="12">
    	<if_matched_sid >200011</if_matched_sid>
    	<match >!ansible|!puppet|!chef</match>
    	<description >Unexpected Sudoers file modification detected</description>
    </rule>
    	 System Startup Scripts 
    <rule id="200016" level="9">
    	<match >/etc/rc.local|/etc/init.d/</match>
    	<description >System startup script modification detected</description>
    </rule>
    <rule id="200017" level="0">
    	<if_matched_sid >200016</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore startup script changes from trusted admin accounts</description>
    </rule>
    <rule id="200019" level="0">
    	<if_matched_sid >200016</if_matched_sid>
    	<match >ansible|puppet|chef</match>
    	<description >Ignore startup script changes from trusted automation tools</description>
    </rule>
    <rule id="200020" level="12">
    	<if_matched_sid >200016</if_matched_sid>
    	<match >!ansible|!puppet|!chef</match>
    	<description >Unexpected system startup script modification detected</description>
    </rule>											
    		 Filesystem Table 											
    		
    <rule id="200021" level="10">
    	<match >/etc/fstab</match>
    	<description >Filesystem table modification detected</description>
    </rule>
    <rule id="200022" level="0">
    	<if_matched_sid >200021</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore filesystem table changes from trusted admin accounts</description>
    </rule>
    <rule id="200024" level="0">
    	<if_matched_sid >200021</if_matched_sid>
    	<match >mount|umount|ansible|puppet|chef</match>
    	<description >Ignore filesystem table changes from trusted programs</description>
    </rule>
    <rule id="200025" level="12">
    	<if_matched_sid >200021</if_matched_sid>
    	<match >!mount|!umount|!ansible|!puppet|!chef</match>
    	<description >Unexpected filesystem table modification detected</description>
    </rule>
    Cron Jobs 
    <rule id="200026" level="9">
    	<match >/etc/crontab|/etc/cron.d/|/etc/cron.daily/|/etc/cron.weekly/</match>
    	<description >Cron job modification detected</description>
    </rule>
    <rule id="200028" level="0">
    	<if_matched_sid >200006</if_matched_sid>
    	<match >ansible|puppet|chef</match>
    	<description >Ignore cron job changes from trusted automation tools</description>
    </rule>
    <rule id="200029" level="12">
    	<if_matched_sid >200006</if_matched_sid>
    	<match >!ansible|!puppet|!chef</match>
    	<description >Unexpected cron job modification detected</description>
    </rule>
    <rule id="200030" level="0">
    	<if_matched_sid >200006</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore cron job changes from trusted admin accounts</description>
    </rule>											
    		 Network Configuration 											
    		
    <rule id="200031" level="9">
    	<match >/etc/network/interfaces|/etc/sysconfig/network-scripts/</match>
    	<description >Network configuration file modification detected</description>
    </rule>
    <rule id="200032" level="0">
    	<if_matched_sid >200031</if_matched_sid>
    	<user >adminuser|sysadmin</user>
    	<description >Ignore network configuration changes from trusted admin										
        accounts</description>
    </rule>
    <rule id="200034" level="0">
    	<if_matched_sid >200031</if_matched_sid>
    	<match >ansible|puppet|chef|nmcli|ifconfig</match>
    	<description >Ignore network configuration changes from trusted programs</description>
    </rule>
    <rule id="200035" level="12">
    	<if_matched_sid >200031</if_matched_sid>
    	<match >!ansible|!puppet|!chef|!nmcli|!ifconfig</match>
    	<description >Unexpected network configuration file modification detected</description>
    </rule>	
</group>
<group name="local,linux,security">
	 <!--Detection of New User Creation -->
	<rule id="300001" level="10">
		<if_group >syslog</if_group>
		<match >useradd|adduser</match>
		<description >New user account created</description>
	</rule>
	<rule id="300002" level="0">
		<if_matched_sid >300001</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore new user creation from trusted admin accounts</description>
	</rule>
	<rule id="300004" level="0">
		<if_matched_sid >300001</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore new user creation from trusted automation tools</description>
	</rule>
	<rule id="300005" level="12">
		<if_matched_sid >300001</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected new user account creation detected</description>
	</rule>
	 <!--Detection of User Deletion -->
	<rule id="300006" level="10">
		<if_group >syslog</if_group>
		<match >userdel</match>
		<description >User account deleted</description>
	</rule>
	<rule id="300007" level="0">
		<if_matched_sid >300006</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore user deletion from trusted admin accounts</description>
	</rule>
	<rule id="300009" level="0">
		<if_matched_sid >300006</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore user deletion from trusted automation tools</description>
	</rule>
	<rule id="300010" level="12">
		<if_matched_sid >300006</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected user account deletion detected</description>
	</rule>
	 <!--Detection of Group Changes -->
	<rule id="300011" level="9">
		<if_group >syslog</if_group>
		<match >groupadd|groupdel|gpasswd</match>
		<description >User group modification detected</description>
	</rule>
	<rule id="300012" level="0">
		<if_matched_sid >300011</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore group changes from trusted admin accounts</description>
	</rule>
	<rule id="300014" level="0">
		<if_matched_sid >300011</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore group changes from trusted automation tools</description>
	</rule>
	<rule id="300015" level="12">
		<if_matched_sid >300011</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected user group modification detected</description>
	</rule>
	 <!--Detection of Package Installation -->
	<rule id="300016" level="8">
		<if_group >syslog</if_group>
		<match >apt-get install|yum install|dnf install</match>
		<description >Software package installation detected</description>
	</rule>
	<rule id="300017" level="0">
		<if_matched_sid >300016</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore package installations from trusted admin accounts</description>
	</rule>
	<rule id="300019" level="0">
		<if_matched_sid >300016</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore package installations from trusted automation tools</description>
	</rule>
	<rule id="300020" level="12">
		<if_matched_sid >300016</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected software package installation detected</description>
	</rule>
	 Detection of Package Removal 
	<rule id="300021" level="8">
		<if_group >syslog</if_group>
		<match >apt-get remove|yum remove|dnf remove</match>
		<description >Software package removal detected</description>
	</rule>
	<rule id="300022" level="0">
		<if_matched_sid >300021</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore package removals from trusted admin accounts</description>
	</rule>
	<rule id="300024" level="0">
		<if_matched_sid >300021</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore package removals from trusted automation tools</description>
	</rule>
	<rule id="300025" level="12">
		<if_matched_sid >300021</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected software package removal detected</description>
	</rule>
	 <!--Detection of Firewall Changes -->
	<rule id="300026" level="10">
		<if_group >syslog</if_group>
		<match >iptables|firewalld|ufw</match>
		<description >Firewall configuration change detected</description>
	</rule>
	<rule id="300027" level="0">
		<if_matched_sid >300026</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore firewall changes from trusted admin accounts</description>
	</rule>
	<rule id="300029" level="0">
		<if_matched_sid >300026</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore firewall changes from trusted automation tools</description>
	</rule>
	<rule id="300030" level="12">
		<if_matched_sid >300026</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected firewall configuration change detected</description>
	</rule>
	 <!--Detection of Suspicious Network Connections -->
	<rule id="300031" level="12">
		<if_group >syslog</if_group>
		<match >connect from|connection attempt</match>
		<description >Suspicious inbound network connection detected</description>
	</rule>
	<rule id="300033" level="0">
		<if_matched_sid >300031</if_matched_sid>
		<match >port 80|port 443</match>
		<description >Ignore inbound connections to allowed services</description>
	</rule>
	 <!--Detection of Privilege Escalation Commands -->
	<rule id="300037" level="12">
		<if_group >syslog</if_group>
		<match >sudo su|sudo -i</match>
		<description >Privilege escalation attempt detected</description>
	</rule>
	<rule id="300038" level="0">
		<if_matched_sid >300037</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore privilege escalation attempts from trusted admin										
    accounts</description>
	</rule>
	<rule id="300040" level="0">
		<if_matched_sid >300037</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore privilege escalation attempts from trusted automation										
    tools</description>
	</rule>
	<rule id="300041" level="12">
		<if_matched_sid >300037</if_matched_sid>
		<user >!adminuser|!sysadmin</user>
		<description >Unexpected privilege escalation attempt detected</description>
	</rule>
	 <!--Detection of Changes to /etc/hosts -->
	<rule id="300042" level="9">
		<match >/etc/hosts</match>
		<description >Hosts file modification detected</description>
	</rule>
	<rule id="300043" level="0">
		<if_matched_sid >300042</if_matched_sid>
		<user >adminuser|sysadmin</user>
		<description >Ignore hosts file changes from trusted admin accounts</description>
	</rule>
	<rule id="300045" level="0">
		<if_matched_sid >300042</if_matched_sid>
		<match >ansible|puppet|chef</match>
		<description >Ignore hosts file changes from trusted automation tools</description>
	</rule>
	<rule id="300046" level="12">
		<if_matched_sid >300042</if_matched_sid>
		<match >!ansible|!puppet|!chef</match>
		<description >Unexpected hosts file modification detected</description>
	</rule>
</group>													
		
```