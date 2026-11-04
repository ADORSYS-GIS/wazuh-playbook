### Wazuh YARA Detection Rules

This document describes a custom Wazuh rule group for YARA malware detections.
It defines a hierarchy of rules for classifying, correlating, and escalating alerts based on YARA scan results.

```
<group name="yara,malware,"> 
  <!-- Base YARA rule --> 
  <rule id="108000" level="0"> 
    <decoded_as>yara_decoder</decoded_as> 
    <description>YARA grouping rule</description> 
  </rule> 
 
  <!-- YARA scan started --> 
  <rule id="108001" level="3"> 
    <if_sid>108000</if_sid> 
    <match>Scan started</match> 
    <description>YARA scan initiated on file</description> 
  </rule> 
 
  <!-- YARA match detected --> 
  <rule id="108002" level="12"> 
    <if_sid>108000</if_sid> 
    <match>wazuh-yara: INFO - Scan result:</match> 
    <description>YARA rule matched: $(yara.rule) - File: $(yara.file)</description> 
    <group>malware,pci_dss_11.4,gdpr_IV_35.7.d,hipaa_164.312.b</group> 
  </rule> 
 
  <!-- Critical malware families --> 
  <rule id="108003" level="15"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(ransomware|cryptolocker|wannacry|petya|ryuk|maze)</field> 
    <description>Critical ransomware detected: $(yara.rule)</description> 
    <group>ransomware,critical,pci_dss_5.2</group> 
  </rule> 
 
  <rule id="108004" level="15"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(trojan|backdoor|rat|remote_access)</field> 
    <description>Trojan/Backdoor detected: $(yara.rule)</description> 
    <group>trojan,critical</group> 
  </rule> 
 
  <rule id="108005" level="14"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(apt|apt[0-9]+|lazarus|cobalt|carbanak)</field> 
    <description>APT malware detected: $(yara.rule)</description> 
    <group>apt,targeted_attack</group> 
  </rule> 
 
  <rule id="108006" level="13"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(miner|cryptominer|coinminer|xmrig)</field> 
    <description>Cryptocurrency miner detected: $(yara.rule)</description> 
    <group>cryptominer</group> 
  </rule> 
 
  <rule id="108007" level="12"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(webshell|shell|c99|r57|b374k)</field> 
    <description>Webshell detected: $(yara.rule)</description> 
    <group>webshell,web_attack</group> 
  </rule> 
 
  <rule id="108008" level="10"> 
    <if_sid>108002</if_sid> 
    <field name="yara_rule" type="pcre2">(?i)(exploit|cve_|vulnerability)</field> 
    <description>Exploit code detected: $(yara.rule)</description> 
    <group>exploit</group> 
  </rule> 
 
  <!-- Specific file type detections --> 
  <rule id="108009" level="13"> 
    <if_sid>108002</if_sid> 
    <field name="yara_file" type="pcre2">\.(exe|dll|sys|scr)$</field> 
    <description>Malicious executable detected: $(yara.file)</description> 
    <group>executable_malware</group> 
  </rule> 
 
  <rule id="108010" level="12"> 
    <if_sid>108002</if_sid> 
    <field name="yara_file" type="pcre2">\.(doc|docx|xls|xlsx|pdf|rtf)$</field> 
    <description>Malicious document detected: $(yara.file)</description> 
    <group>document_malware</group> 
  </rule> 
 
  <!-- YARA scan errors --> 
  <rule id="108011" level="5"> 
    <if_sid>108000</if_sid> 
    <match>Error|Failed</match> 
    <description>YARA scan error occurred</description> 
  </rule> 
 
  <!-- No match found (informational) --> 
  <rule id="108012" level="3"> 
    <if_sid>108000</if_sid> 
    <match>No matches</match> 
    <description>YARA scan completed - No threats detected</description> 
  </rule> 
  
  <!--User action-->
  <rule id="108013" level="3">
        <if_sid>108000</if_sid>
        <field name="log_type">SUCCESS</field>
        <description>Yara action '$(yara_action)', completed with success on file: $(yara_scanned_file)</description>
    </rule>
    
 <rule id="108014" level="7">
        <if_sid>108000</if_sid>
        <field name="log_type">ERROR</field>
        <description>Yara action: '$(yara_action)', failed on file: $(yara_scanned_file)</description>
    </rule>
</group> 
````