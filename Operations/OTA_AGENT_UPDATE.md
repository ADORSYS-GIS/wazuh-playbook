## OTA Agent Update Playbook

### Objective  
Trigger OTA (Over-The-Air) agent updates on host machines **without requiring user intervention**. This can be done either from the **Wazuh Manager** or the **Wazuh Dashboard**.

---

## 1. OTA Update via Wazuh Manager

Access the **Wazuh Manager Master Node** and perform the following steps:

### Step 1: Authenticate and Retrieve Token
```bash
curl -u wazuh-wui:9Y0m^%^Cx4zx@6=X -k -X POST "https://wazuh-manager-master-0:55000/security/user/authenticate"
```

### Step 2: Export Token to Environment Variable
```bash
export TOKEN=<your-token>
```

### Step 3: Trigger OTA Update Command

#### All Agents
```bash
curl -k -X PUT "https://wazuh-manager-master-0:55000/active-response" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
           "command": "!adorsys-update.sh"
         }'
```

#### Specific Agents
Use the `agents_list` query parameter with comma-separated agent IDs:
```bash
curl -k -X PUT "https://wazuh-manager-master-0:55000/active-response?agents_list=002,003" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
           "command": "!adorsys-update.sh"
         }'
```

---

## 2. OTA Update via Wazuh Dashboard

A more user-friendly alternative using the Wazuh Dashboard:

### Navigation  
Go to **Dev Tools** under **Server Management**, and execute the following API calls:

#### All Agents
```json
PUT /active-response
{
  "command": "!adorsys-update.sh"
}
```

#### Specific Agent(s)
Use the `agents_list` parameter with the desired agent IDs:
```json
PUT /active-response?agents_list=001,002
{
  "command": "!adorsys-update.sh"
}
```
