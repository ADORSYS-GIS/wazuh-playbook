# 🛡️ **Wazuh Agent Migration Playbook (Cross-Platform)**

## 🎯 Purpose

This playbook describes how to:

* Transfer the Wazuh Agent’s configuration (`etc` folder) to a new machine
* Reinstall the agent using standard enrollment procedures
* Reapply configuration while reusing agent identity
* Restart and verify the agent is properly connected

> ✅ Supports: Linux, macOS, and Windows

---

## 🔁 Transfer Procedure

### **Step 1: Backup the Configuration Folder**

1. On the **old machine**, locate the Wazuh Agent installation directory:

   | Platform | Default Path to `etc` Folder             |
   | -------- | ---------------------------------------- |
   | Windows  | `C:\Program Files (x86)\ossec-agent\etc` |
   | macOS    | `/Library/Ossec/etc`                     |
   | Linux    | `/var/ossec/etc`                         |

2. Copy the **entire `etc` folder** to a temporary backup location of your choice:

---

### **Step 2: Uninstall the Existing Wazuh Agent**

1. Follow the enrollment guide provided here:
   🔗 [Wazuh Agent Enrollment – adorsys GitHub](https://github.com/ADORSYS-GIS/wazuh-agent/tree/main/Agent%20Enrollment)

2. Do **not** delete the backed-up `etc` folder.

---

### **Step 3: Reinstall the Agent Using the Standard Enrollment Process**

Follow the enrollment guide provided here:
   🔗 [Wazuh Agent Enrollment – adorsys GitHub](https://github.com/ADORSYS-GIS/wazuh-agent/tree/main/Agent%20Enrollment)

> ⚠️ Ensure the agent is **not yet started** if possible, or stop it after install before continuing.

---

### **Step 4: Apply the Previous Configuration**

Copy the **backed-up `etc` folder** into the new agent's installation path, **replacing only configuration files**.

   | Platform | Replace at Path                          |
   | -------- | ---------------------------------------- |
   | Windows  | `C:\Program Files (x86)\ossec-agent\etc` |
   | macOS    | `/Library/Ossec/etc`                     |
   | Linux    | `/var/ossec/etc`                         |

---

### **Step 5: Restart the Agent and Confirm**

1. Start or restart the Wazuh agent:

    a. **Linux:**
    ```bash
    sudo /var/ossec/bin/wazuh-control restart
    ```
    b. **MacOs:**
    ```bash
    sudo /Library/Ossec/bin/wazuh-control restart
    ```
    c. **Windows:**
    ```powershell
    Restart-Service -Name "WazuhSvc"
    ```

2. Wait for 5-10 minutes and confirm that the agent:

   * Appears in the Wazuh dashboard
   * Has the **same ID**
   * Shows as **active/online**

---

## ✅ Final Checklist

| Task                                              | Done |
| ------------------------------------------------- | ---- |
| Backed up `etc` folder                            |      |
| Uninstalled Wazuh agent using enrollment guide    |      |
| Reinstalled agent using enrollment guide          |      |
| Restored custom config from `etc` backup          |      |
| Restarted agent and verified online status        |      |
