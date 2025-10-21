# 🛡️ Wazuh Agentless Monitoring Setup Guide
**By:** Ju-nine.Ngu  
**Duration:** 1 min  

Configure agentless monitoring for systems that can't run Wazuh agents

## 🎯 What You'll Accomplish
By the end of this guide, you'll have agentless monitoring configured in Wazuh, allowing you to monitor critical systems without installing agents on target devices.

## 🚀 When to Use Agentless Monitoring
Use agentless monitoring when you need to monitor:
- **🏛️ Legacy Systems** - Old systems that can't run modern Wazuh agents
- **🌐 Network Devices** - Routers, firewalls, switches with SSH access
- **🔒 Restricted Environments** - Systems where you can't install software
- **☁️ Cloud Infrastructure** - Temporary or ephemeral instances

## 🔧 Configuration Overview
Agentless monitoring uses SSH to connect to target systems and run monitoring commands.

### 📁 What Gets Monitored
- **File Integrity** - Track changes to critical files and directories
- **Command Output** - Monitor output of periodic commands
- **System Configuration** - Watch for configuration changes

## 🔑 Prerequisites
- A running Wazuh server that you have access to
- Target systems with SSH installed and enabled
- Administrative access to both Wazuh server and target systems

## 🛠️ Setup Process
### 🚀 Phase 1: Automated SSH Setup
- Run our comprehensive automation script
- Script handles SSH keys, legacy compatibility, and host registration
- Works with both modern systems and 20+ year old legacy systems

### ⚙️ Phase 2: Wazuh Configuration
- Add agentless monitoring rules to ossec.conf
- Restart wazuh-manager service

### ✅ Phase 3: Verification
- Confirm systems appear in agent list
- Check logs for successful monitoring
- Verify dashboard shows monitoring data

## 🚀 Implementation Guide
This guide includes:
- **Automated setup script** - Copy, paste, and run
- **Modern & legacy system support** - RHEL 4.4 to RHEL 10
- **Idempotent operation** - Safe to run multiple times
- **Complete troubleshooting** - Solutions for common issues

## 📚 References
- [Wazuh Agentless Monitoring Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/agentless-monitoring/index.html)
- [Wazuh Configuration Reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/agentless.html)
