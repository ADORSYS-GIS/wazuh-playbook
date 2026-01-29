### Suricata Rules
Suricata rules are patterns and conditions that tell Suricata what network traffic to detect, how to classify it, and what alerts to generate.
They allow Suricata to function as an IDS (Intrusion Detection System) or IPS (Intrusion Prevention System) by analyzing packets and identifying suspicious or malicious behavior. 

```xml
<group name="ids,suricata,">

  <!-- ===================================== -->
  <!-- Suricata Alert Processing and Mapping -->
  <!-- ===================================== -->

  <!-- Specific Signature Matches (parent: 86600) -->

  <!-- SQL Injection Detection -->
  <rule id="100001" level="10">
    <if_sid>86600</if_sid>
    <field name="alert.signature">SQL Injection Attempt Detected</field>
    <description>SQL Injection attack detected</description>
    <group>web,attack,sql_injection,</group>
  </rule>

  <!-- SSH Brute Force Attack -->
  <rule id="100002" level="10">
    <if_sid>86600</if_sid>
    <match>Possible SSH Brute Force Attack</match>
    <description>SSH brute force attack detected</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <!-- Malware C2 Communication -->
  <rule id="100003" level="12">
    <if_sid>86600</if_sid>
    <match>Potential C2 Beacon Traffic</match>
    <description>Command and Control communication detected</description>
    <group>malware,trojan,</group>
  </rule>

  <!-- Ransomware Activity -->
  <rule id="100004" level="13">
    <if_sid>86600</if_sid>
    <match>Potential Ransomware Activity</match>
    <description>Ransomware file encryption activity detected</description>
    <group>malware,ransomware,</group>
  </rule>

  <!-- Reverse Shell -->
  <rule id="100005" level="12">
    <if_sid>86600</if_sid>
    <match>Potential Reverse Shell Connection</match>
    <description>Reverse shell connection attempt detected</description>
    <group>exploit,intrusion_attempt,</group>
  </rule>

  <!-- Port Scanning -->
  <rule id="100006" level="7">
    <if_sid>86600</if_sid>
    <match>Port Scan Detected</match>
    <description>Network port scanning activity detected</description>
    <group>recon,pci_dss_11.4,</group>
  </rule>

  <!-- XSS Attack -->
  <rule id="100007" level="9">
    <if_sid>86600</if_sid>
    <match>Cross-Site Scripting</match>
    <description>XSS attack attempt detected</description>
    <group>web,attack,xss,</group>
  </rule>

  <!-- DNS Tunneling -->
  <rule id="100008" level="8">
    <if_sid>86600</if_sid>
    <match>Possible DNS Tunneling Detected</match>
    <description>DNS tunneling data exfiltration detected</description>
    <group>policy_violation,data_exfiltration,</group>
  </rule>

  <!-- Severity-based Rules (parent: 86601) -->

  <!-- High severity: alert.severity = 1 -->
  <rule id="100009" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.severity">1</field>
    <description>Suricata high severity alert (1): ${alert.signature}</description>
    <group>suricata,high_severity,</group>
  </rule>

  <!-- Medium severity: alert.severity = 2 -->
  <rule id="100010" level="7">
    <if_sid>86601</if_sid>
    <field name="alert.severity">2</field>
    <description>Suricata medium severity alert (2): ${alert.signature}</description>
    <group>suricata,medium_severity,</group>
  </rule>

  <!-- Low severity: alert.severity = 3 -->
  <rule id="100011" level="3">
    <if_sid>86601</if_sid>
    <field name="alert.severity">3</field>
    <description>Suricata low severity alert (3): ${alert.signature}</description>
    <group>suricata,low_severity,</group>
  </rule>

  <!-- ===================================== -->
  <!-- Whitelisting / Suppression Rules      -->
  <!-- ===================================== -->

  <!-- SQL Injection Whitelists -->
  <rule id="110010" level="0">
    <if_sid>100001</if_sid>
    <srcip>10.0.1.50</srcip>
    <description>SQL Injection - Whitelisted application server</description>
  </rule>

  <rule id="110011" level="0">
    <if_sid>100001</if_sid>
    <url>/api/search|/legitimate-endpoint</url>
    <description>SQL Injection - Whitelisted endpoint</description>
  </rule>

  <!-- SSH Brute Force Whitelists -->
  <rule id="110012" level="0">
    <if_sid>100002</if_sid>
    <srcip>192.168.1.100</srcip>
    <description>SSH Brute Force - Whitelisted jump server</description>
  </rule>

  <rule id="110013" level="0">
    <if_sid>100002</if_sid>
    <srcip>10.0.0.0/8</srcip>
    <description>SSH Brute Force - Internal network excluded</description>
  </rule>

  <!-- Malware C2 Whitelists -->
  <rule id="110014" level="0">
    <if_sid>100003</if_sid>
    <dstport>443|80</dstport>
    <hostname>known-cdn.com|trusted-service.com</hostname>
    <description>C2 Traffic - Whitelisted CDN/services</description>
  </rule>

  <!-- Ransomware Whitelists -->
  <rule id="110015" level="0">
    <if_sid>100004</if_sid>
    <srcip>10.0.2.10</srcip>
    <description>Ransomware - Whitelisted backup server</description>
  </rule>

  <rule id="110016" level="0">
    <if_sid>100004</if_sid>
    <user>backup_service|veeam</user>
    <description>Ransomware - Whitelisted backup service account</description>
  </rule>

  <!-- Reverse Shell Whitelists -->
  <rule id="100109" level="0">
    <if_sid>100005</if_sid>
    <srcip>10.0.3.0/24</srcip>
    <description>Reverse Shell - Whitelisted DevOps subnet</description>
  </rule>

  <rule id="100117" level="0">
    <if_sid>100005</if_sid>
    <program_name>ansible|puppet|chef</program_name>
    <description>Reverse Shell - Whitelisted automation tools</description>
  </rule>

  <!-- Port Scan Whitelists -->
  <rule id="100111" level="0">
    <if_sid>100006</if_sid>
    <srcip>10.0.4.20</srcip>
    <description>Port Scan - Whitelisted security scanner</description>
  </rule>

  <rule id="100112" level="0">
    <if_sid>100006</if_sid>
    <hostname>nessus.company.com|qualys-scanner</hostname>
    <description>Port Scan - Whitelisted scanning tools</description>
  </rule>

  <!-- XSS Whitelists -->
  <rule id="100113" level="0">
    <if_sid>100007</if_sid>
    <url>/admin/editor|/cms/content</url>
    <description>XSS - Whitelisted CMS editor</description>
  </rule>

  <rule id="100114" level="0">
    <if_sid>100007</if_sid>
    <srcip>10.0.5.0/24</srcip>
    <description>XSS - Whitelisted admin network</description>
  </rule>

  <!-- DNS Tunneling Whitelists -->
  <rule id="100115" level="0">
    <if_sid>100008</if_sid>
    <regex>.*\.cloudfront\.net|.*\.akamai\.net</regex>
    <description>DNS Tunneling - Whitelisted CDN domains (using regex for wildcard support)</description>
  </rule>

  <rule id="100116" level="0">
    <if_sid>100008</if_sid>
    <match>_dmarc|_domainkey</match>
    <description>DNS Tunneling - Whitelisted DNS records</description>
  </rule>

  <!-- User-based Exclusions (applies to multiple rules) -->
  <rule id="100120" level="0">
    <if_sid>100001,100007</if_sid>
    <user>admin|developer|qa_tester</user>
    <description>Web attacks (SQLi/XSS) - Whitelisted testing accounts</description>
  </rule>

  <!-- Example: IP whitelist from external list (uncomment if needed) -->
  <!--
  <rule id="100122" level="0">
    <if_sid>100001,100002,100003</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/whitelist_ips</list>
    <description>Whitelisted IP from list</description>
  </rule>
  -->

</group>
```
