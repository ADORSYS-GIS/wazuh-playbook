### Suricata Rules
Suricata rules are patterns and conditions that tell Suricata what network traffic to detect, how to classify it, and what alerts to generate.
They allow Suricata to function as an IDS (Intrusion Detection System) or IPS (Intrusion Prevention System) by analyzing packets and identifying suspicious or malicious behavior.

<group name="ids,suricata,">
	<!-- SQL Injection Detection -->
    <rule id="100001" level="10">
      <if_sid>86600</if_sid>
      <field name="alert.signature">SQL Injection Attempt Detected</field>
      <description>SQL Injection attack detected</description>
      <group>web,attack,sql_injection</group>
    </rule>
	<rule id="110010" level="0">
		<if_sid>100001</if_sid>
		<srcip>10.0.1.50</srcip>
		 Your legitimate app server 
		<description>SQL Injection - Whitelisted application server</description>
	</rule>
	<rule id="110011" level="0">
		<if_sid>100001</if_sid>
		<url>/api/search|/legitimate-endpoint</url>
		<description>SQL Injection - Whitelisted endpoint</description>
	</rule>
	 SSH Brute Force Attack 
	<rule id="100002" level="10">
		<if_sid>86600</if_sid>
		<match>Possible SSH Brute Force Attack</match>
		<description>SSH brute force attack detected</description>
		<group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5</group>
	</rule>
	<rule id="110012" level="0">
		<if_sid>100002</if_sid>
		<srcip>192.168.1.100</srcip>
		 Your jump server 
		<description>SSH Brute Force - Whitelisted jump server</description>
	</rule>
	<rule id="110013" level="0">
		<if_sid>100002</if_sid>
		<srcip>10.0.0.0/8</srcip>
		 Internal network 
		<description>SSH Brute Force - Internal network excluded</description>
	</rule>
	 Malware C2 Communication 
	<rule id="100003" level="12">
		<if_sid>86600</if_sid>
		<match>Potential C2 Beacon Traffic</match>
		<description>Command and Control communication detected</description>
		<group>malware,trojan</group>
	</rule>
	<rule id="110014" level="0">
		<if_sid>100003</if_sid>
		<dstport>443|80</dstport>
		<hostname>known-cdn.com|trusted-service.com</hostname>
		<description>C2 Traffic - Whitelisted CDN/services</description>
	</rule>
	 Ransomware Activity 
	<rule id="100004" level="13">
		<if_sid>86600</if_sid>
		<match>Potential Ransomware Activity</match>
		<description>Ransomware file encryption activity detected</description>
		<group>malware,ransomware</group>
	</rule>
	<rule id="110015" level="0">
		<if_sid>100004</if_sid>
		<srcip>10.0.2.10</srcip>
		 Backup server 
		<description>Ransomware - Whitelisted backup server</description>
	</rule>
	<rule id="110016" level="0">
		<if_sid>100004</if_sid>
		<user>backup_service|veeam</user>
		<description>Ransomware - Whitelisted backup service account</description>
	</rule>
	 Reverse Shell 
	<rule id="100005" level="12">
		<if_sid>86600</if_sid>
		<match>Potential Reverse Shell Connection</match>
		<description>Reverse shell connection attempt detected</description>
		<group>exploit,intrusion_attempt</group>
	</rule>
	<rule id="100109" level="0">
		<if_sid>100005</if_sid>
		<srcip>10.0.3.0/24</srcip>
		 DevOps subnet 
		<description>Reverse Shell - Whitelisted DevOps subnet</description>
	</rule>
	<rule id="100117" level="0">
		<if_sid>100005</if_sid>
		<program_name>ansible|puppet|chef</program_name>
		<description>Reverse Shell - Whitelisted automation tools</description>
	</rule>
	 Port Scanning 
	<rule id="100006" level="7">
		<if_sid>86600</if_sid>
		<match>Port Scan Detected</match>
		<description>Network port scanning activity detected</description>
		<group>recon,pci_dss_11.4</group>
	</rule>
	<rule id="100111" level="0">
		<if_sid>100006</if_sid>
		<srcip>10.0.4.20</srcip>
		 Vulnerability scanner 
		<description>Port Scan - Whitelisted security scanner</description>
	</rule>
	<rule id="100112" level="0">
		<if_sid>100006</if_sid>
		<hostname>nessus.company.com|qualys-scanner</hostname>
		<description>Port Scan - Whitelisted scanning tools</description>
	</rule>
	 XSS Attack 
	<rule id="100007" level="9">
		<if_sid>86600</if_sid>
		<match>Cross-Site Scripting</match>
		<description>XSS attack attempt detected</description>
		<group>web,attack,xss</group>
	</rule>
	<rule id="100113" level="0">
		<if_sid>100007</if_sid>
		<url>/admin/editor|/cms/content</url>
		<description>XSS - Whitelisted CMS editor</description>
	</rule>
	<rule id="100114" level="0">
		<if_sid>100007</if_sid>
		<srcip>10.0.5.0/24</srcip>
		 Admin subnet 
		<description>XSS - Whitelisted admin network</description>
	</rule>
	 DNS Tunneling 
	<rule id="100008" level="8">
		<if_sid>86600</if_sid>
		<match>Possible DNS Tunneling Detected</match>
		<description>DNS tunneling data exfiltration detected</description>
		<group>policy_violation,data_exfiltration</group>
	</rule>
	<rule id="100115" level="0">
		<if_sid>100008</if_sid>
		<hostname>.*\.cloudfront\.net|.*\.akamai\.net</hostname>
		<description>DNS Tunneling - Whitelisted CDN domains</description>
	</rule>
	<rule id="100116" level="0">
		<if_sid>100008</if_sid>
		<match>_dmarc|_domainkey</match>
		<description>DNS Tunneling - Whitelisted DNS records</description>
	</rule>
	 User-based Exclusions 
	<rule id="100120" level="0">
		<if_sid>100001,100007</if_sid>
		<user>admin|developer|qa_tester</user>
		<description>Web attacks - Whitelisted testing accounts</description>
	</rule>
	<rule id="100122" level="0">
		<if_sid>100001,100002,100003</if_sid>
		<list field="srcip" lookup="address_match_key">etc/lists/whitelist_ips</list>
		<description>Whitelisted IP from list</description>
	</rule>
</group>