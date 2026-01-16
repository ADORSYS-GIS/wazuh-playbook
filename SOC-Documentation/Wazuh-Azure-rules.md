# Azure Wazuh Rules Documentation

## Document Information
- **Version:** 1.0
- **Last Updated:** January 14, 2026
- **Purpose:** Comprehensive reference for Azure monitoring rules in Wazuh

---

## Overview

This document contains all Azure monitoring rules for Wazuh SOC, covering Microsoft Entra ID (formerly Azure AD) authentication events and Azure Activity Log (control plane) operations.

### Key Features
- **Noise Reduction:** Intelligent filtering of benign events
- **Risk-Based Alerting:** Focus on high-signal security events
- **Correlation Rules:** Detect brute-force and distributed attacks
- **Compliance Coverage:** IAM changes, logging tampering, privilege escalation

### Dependencies
- **Parent Rule ID:** 87802 (Entra ID events)
- **Location Filter:** "Azure" (Activity Log events)

---

### Rule ID Ranges
| Range 		| Purpose 							 |
|---------------|------------------------------------|
| 110010-110012 | Noise reduction (level 0) 		 |
| 110020-110022 | Failed authentication + correlation|
| 110030-110035 | High-signal Entra ID alerts 		 |
| 110100-110199 | Azure Activity Log alerts 		 |

### Alert Levels
| Level | Severity 		| Examples 									  |
|-------|---------------|---------------------------------------------|
| 0 	| Silenced 		| Normal sign-ins, allowlisted IPs 			  |		  
| 5-7 	| Low-Medium 	| Single auth failures, CA issues 			  |
| 8-10 	| Medium-High 	| Device risks, policy changes 				  |	
| 11-13 | High-Critical | IAM changes, credential access, brute-force |

---

### Complete Rule Configuration Block

```xml
<group name="azure,">
	<!-- =========================================================
	ENTRA ID (Microsoft Entra ID) NOISE REDUCTION RULES
	========================================================= -->
	
	<!-- SILENCE: Normal successful sign-ins (low/no risk) -->
	<rule id="110010" level="0">
		<if_sid>87802</if_sid>
		<field name="status.errorCode" type="pcre2">^0$</field>
		<field name="conditionalAccessStatus" type="pcre2">^success$</field>
		<field name="riskState" type="pcre2">^none$</field>
		<description>Azure: Entra sign-in success (low/no risk) - silenced</description>
		<group>azure_entra,noise</group>
	</rule>
	
	<!-- SILENCE: Sign-ins from allowlisted IPs (CDB list) -->
	<rule id="110011" level="0">
		<if_sid>87802</if_sid>
		<list field="ipAddress" lookup="address_match_key">etc/lists/azure_allowed_ips</list>
		<description>Azure: Entra sign-in from allowlisted IP - silenced</description>
		<group>azure_entra,noise,allowlist</group>
	</rule>
	
	<!-- SILENCE: Sign-ins from allowlisted users (CDB list) -->
	<rule id="110012" level="0">
		<if_sid>87802</if_sid>
		<list field="userPrincipalName" lookup="match_key">etc/lists/azure_allowed_users</list>
		<description>Azure: Entra sign-in from allowlisted user - silenced</description>
		<group>azure_entra,noise,allowlist</group>
	</rule>
	
	<!-- =========================================================
	ENTRA ID (Microsoft Entra ID) HIGH-SIGNAL ALERT RULES
	========================================================= -->
	
	<!-- ALERT: Any sign-in with risk level High/Medium -->
	<rule id="110030" level="12">
		<if_sid>87802</if_sid>
		<field name="riskLevelDuringSignIn" type="pcre2">^(high|medium)$</field>
		<description>Azure: Entra risky sign-in (risk=$(riskLevelDuringSignIn)) user=$(userPrincipalName) ip=$(ipAddress)</description>
		<group>azure_entra,risky_signin</group>
	</rule>
	
	<!-- ALERT: Risk state not 'none' (covers other risk-state values) -->
	<rule id="110031" level="10">
		<if_sid>87802</if_sid>
		<field name="riskState" negate="yes" type="pcre2">^none$</field>
		<description>Azure: Entra sign-in riskState=$(riskState) user=$(userPrincipalName) ip=$(ipAddress)</description>
		<group>azure_entra,risky_signin</group>
	</rule>
	
	<!-- ALERT: Legacy / non-interactive client app used -->
	<rule id="110032" level="9">
		<if_sid>87802</if_sid>
		<field name="clientAppUsed" type="pcre2">^(Other clients|IMAP|POP|SMTP|Exchange ActiveSync)$</field>
		<description>Azure: Entra sign-in using legacy clientAppUsed=$(clientAppUsed) user=$(userPrincipalName) ip=$(ipAddress)</description>
		<group>azure_entra,legacy_auth</group>
	</rule>
	
	<!-- ALERT: Sign-in from an unmanaged device -->
	<rule id="110033" level="8">
		<if_sid>87802</if_sid>
		<field name="deviceDetail.isManaged" type="pcre2">^false$</field>
		<description>Azure: Entra sign-in from unmanaged device user=$(userPrincipalName) device=$(deviceDetail.displayName) ip=$(ipAddress)</description>
		<group>azure_entra,device_risk</group>
	</rule>
	
	<!-- ALERT: Sign-in from a non-compliant device -->
	<rule id="110034" level="8">
		<if_sid>87802</if_sid>
		<field name="deviceDetail.isCompliant" type="pcre2">^false$</field>
		<description>Azure: Entra sign-in from non-compliant device user=$(userPrincipalName) device=$(deviceDetail.displayName) ip=$(ipAddress)</description>
		<group>azure_entra,device_risk</group>
	</rule>
	
	<!-- ALERT: Conditional Access failure (blocked / failed CA) -->
	<rule id="110035" level="7">
		<if_sid>87802</if_sid>
		<field name="conditionalAccessStatus" negate="yes" type="pcre2">^success$</field>
		<description>Azure: Entra conditional access status=$(conditionalAccessStatus) user=$(userPrincipalName) ip=$(ipAddress)</description>
		<group>azure_entra,conditional_access</group>
	</rule>
	
	<!-- =========================================================
	ENTRA ID AUTH FAILURE + CORRELATION (NOISE-REDUCED)
	Uses frequency/timeframe + ignore to reduce spam.
	Uses same_field to correlate on dynamic JSON fields.
	========================================================= -->
	
	<!-- Base: One failed sign-in (keep this LOW to avoid noise) -->
	<rule id="110020" level="5">
		<if_sid>87802</if_sid>
		<field name="status.errorCode" negate="yes" type="pcre2">^0$</field>
		<description>Azure: Entra sign-in failed user=$(userPrincipalName) ip=$(ipAddress) errorCode=$(status.errorCode)</description>
		<group>azure_entra,authentication_failed</group>
	</rule>
	
	<!-- CORRELATED: Many failures from the same IP (brute force from one source) -->
	<rule id="110021" level="12" frequency="10" timeframe="300" ignore="1800">
		<if_matched_sid>110020</if_matched_sid>
		<same_field>ipAddress</same_field>
		<description>Azure: Entra brute-force suspected (10 fails/5m) srcIP=$(ipAddress)</description>
		<group>azure_entra,bruteforce</group>
	</rule>
	
	<!-- CORRELATED: Many failures against the same user (password guessing on one account) -->
	<rule id="110022" level="10" frequency="6" timeframe="300" ignore="1800">
		<if_matched_sid>110020</if_matched_sid>
		<same_field>userPrincipalName</same_field>
		<description>Azure: Entra account under attack (6 fails/5m) user=$(userPrincipalName)</description>
		<group>azure_entra,bruteforce</group>
	</rule>
	
	<!-- =========================================================
	AZURE ACTIVITY LOG (ARM / CONTROL PLANE) - HIGH VALUE ALERTS
	IMPORTANT:
	- Field names depend on your Log Analytics query output.
	- These rules assume common AzureActivity columns like:
	  OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, 
	  ResourceId, SubscriptionId.
	- If your schema differs, rename fields accordingly.
	========================================================= -->
	
	<!-- OPTIONAL SILENCE: Control-plane "read" operations are noisy.
	     Uncomment if you ingest lots of read operations and want them suppressed. -->
	<!--
	<rule id="110100" level="0">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">\/read$</field>
		<description>Azure: Control-plane read operation - silenced</description>
		<group>azure_activity,noise</group>
	</rule>
	-->
	
	<!-- ALERT: Role assignment created/updated (privilege changes) -->
	<rule id="110110" level="13">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Authorization\/roleAssignments\/write$</field>
		<description>Azure: Role assignment WRITE (privilege change) caller=$(Caller) ip=$(CallerIpAddress) resource=$(ResourceId)</description>
		<group>azure_activity,iam,privilege_change</group>
	</rule>
	
	<!-- ALERT: Role assignment deleted -->
	<rule id="110111" level="12">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Authorization\/roleAssignments\/delete$</field>
		<description>Azure: Role assignment DELETE (privilege change) caller=$(Caller) ip=$(CallerIpAddress) resource=$(ResourceId)</description>
		<group>azure_activity,iam,privilege_change</group>
	</rule>
	
	<!-- ALERT: Custom role definition changed -->
	<rule id="110112" level="12">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Authorization\/roleDefinitions\/(write|delete)$</field>
		<description>Azure: Role definition modified caller=$(Caller) ip=$(CallerIpAddress) resource=$(ResourceId)</description>
		<group>azure_activity,iam,privilege_change</group>
	</rule>
	
	<!-- ALERT: Azure Policy assignment/definition changes -->
	<rule id="110120" level="10">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Authorization\/policy(Assignments|Definitions|SetDefinitions)\/(write|delete)$</field>
		<description>Azure: Policy changed operation=$(OperationNameValue) caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,policy_change</group>
	</rule>
	
	<!-- ALERT: Diagnostic settings / logging pipeline modified -->
	<rule id="110121" level="10">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Insights\/diagnosticSettings\/(write|delete)$</field>
		<description>Azure: Diagnostic settings changed caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,logging_tamper</group>
	</rule>
	
	<!-- ALERT: Resource lock removed or modified (often used to prevent deletion) -->
	<rule id="110122" level="9">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Authorization\/locks\/(delete|write)$</field>
		<description>Azure: Resource lock changed operation=$(OperationNameValue) caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,defense_evasion</group>
	</rule>
	
	<!-- ALERT: NSG security rules changed -->
	<rule id="110123" level="10">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Network\/networkSecurityGroups\/securityRules\/(write|delete)$</field>
		<description>Azure: NSG security rule changed operation=$(OperationNameValue) caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,network_change</group>
	</rule>
	
	<!-- ALERT: Azure Firewall / Firewall Policy changed -->
	<rule id="110124" level="10">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Network\/(azureFirewalls|firewallPolicies)\/(write|delete)$</field>
		<description>Azure: Firewall changed operation=$(OperationNameValue) caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,network_change</group>
	</rule>
	
	<!-- ALERT: Key Vault access policy changed -->
	<rule id="110130" level="13">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.KeyVault\/vaults\/accessPolicies\/write$</field>
		<description>Azure: Key Vault access policy changed caller=$(Caller) ip=$(CallerIpAddress) vault=$(ResourceId)</description>
		<group>azure_activity,keyvault,credential_access</group>
	</rule>
	
	<!-- ALERT: Storage account keys listed/regenerated (high risk) -->
	<rule id="110140" level="13">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Storage\/storageAccounts\/(listKeys|regenerateKey)\/action$</field>
		<description>Azure: Storage account keys accessed operation=$(OperationNameValue) caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,storage,credential_access</group>
	</rule>
	
	<!-- ALERT: VM extension write (common attacker technique for code execution) -->
	<rule id="110150" level="11">
		<location>Azure</location>
		<field name="OperationNameValue" type="pcre2">^Microsoft\.Compute\/virtualMachines\/extensions\/write$</field>
		<description>Azure: VM extension WRITE caller=$(Caller) resource=$(ResourceId)</description>
		<group>azure_activity,compute,persistence</group>
	</rule>
</group>
```