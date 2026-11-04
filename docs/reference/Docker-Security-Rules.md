# Wazuh Custom Rules: Docker Security & Operational Monitoring

## Executive Summary
This document details the custom Wazuh rules implemented to enhance Docker infrastructure security monitoring. The ruleset is designed to provide high-fidelity alerts for critical container lifecycle events, suspicious interactive access, data egress attempts, and cluster-level configuration changes, while minimizing operational noise from routine infrastructure services.

## Rule Groups Overview

### 1. Docker Lifecycle & Operational Events (`docker_custom`)
These rules monitor core container actions, ensuring that changes to container states are accurately captured with appropriate severity levels.

| Rule ID | Level | Action | Description |
|---------|-------|--------|-------------|
| **87903** | 5 | `start` | Container started. Includes container and image names. |
| **87904** | 7 | `stop` | Container stopped. Critical for availability monitoring. |
| **87905** | 8 | `pause` | Container paused (potential availability impact). |
| **87906** | 5 | `unpause`| Container resumed from paused state. |
| **100100**| 9 | `restart`| Container restarted. Often indicates instability. |
| **100101**| 11 | `kill/die`| Container terminated unexpectedly. High severity. |
| **100111**| 10 | `oom` | **Out-Of-Memory (OOM)** condition detected in container. |

### 2. Security & Suspicious Activity
High-severity rules targeting potential post-exploitation activity, data theft, or evasion techniques.

| Rule ID | Level | Category | Description |
|---------|-------|----------|-------------|
| **87907** | 12 | **Suspicious** | **Interactive shell** (bash/sh/dash) started in a running container. |
| **100102**| 10 | Execution | Non-interactive command execution detected in container. |
| **100103**| 11 | File Transfer| File copied **from host to container** (`extract-to-dir`). |
| **100104**| 11 | Data Egress | File copied **from container to host** (`archive-path`). |
| **100105**| 11 | Data Egress | Container filesystem **exported**. |
| **100106**| 11 | Data Egress | Image **pushed** or **saved** (potential exfiltration of intellectual property). |
| **100140**| 11 | Access | Interactive **attach** to a running container. |
| **100141**| 12 | Persistence | Container state **committed** to a new image (evidence preservation or malware staging). |
| **100142**| 9 | Evasion | Container **renamed** (potential attempt to hide presence). |

### 3. Noise Reduction & Tuning (`docker_noise_reduction`)
To maintain high signal-to-noise ratio, routine events from trusted infrastructure are suppressed (Level 0).

*   **Infrastructure Containers:** Silent lifecycle events for `nginx-proxy`, `traefik`, `node-exporter`, `cadvisor`, `portainer`, and `watchtower`.
*   **Trusted Images:** Suppressed starts from Prometheus, Grafana, Traefik, and Portainer images.
*   **Healthchecks:** Healthy status updates are silenced, while **Unhealthy** transitions remain at Level 10 (**Rule 100126**).
*   **Automated Execs:** Silenced routine commands from `backup`, `certbot`, or trivial commands like `echo` or `true`.
*   **Ephemeral Workloads:** Silenced network connect/disconnect and create/destroy actions for CI/CD runners (identified by prefixes like `job-`, `runner-`, `build-`).

### 4. Correlation & Incident Detection
Rules that detect patterns of behavior indicative of larger issues or attacks.

| Rule ID | Level | Logic | Description |
|---------|-------|-------|-------------|
| **100112**| 12 | 3 events in 5m | **Restart Storm**: Container crashing and restarting rapidly. |
| **100113**| 13 | 3 events in 10m| **Lateral Movement**: Multiple shell sessions started in one container. |
| **100132**| 12 | 5 events in 10m| Rapid restarts even in "approved" monitoring/infra containers. |

### 5. Infrastructure & Control Plane (`docker_additional_high_value`)
Monitoring critical changes to the Docker daemon, network, and orchestration.

*   **Secrets & Configs:** Creation, update, or removal of Docker Secrets (**Rule 100150, 100109**) and Configs (**Rule 100151, 100110**).
*   **Networking:** Monitoring network destruction or unexpected disconnections (**Rule 100108**).
*   **Daemon Monitoring:** Detection of configuration reloads (**Rule 100146**).
*   **Swarm Monitoring:** Tracking lifecycle changes to Swarm Services (**Rule 100148**) and Cluster Nodes (**Rule 100149**).
*   **Persistent Storage:** Alerts when Docker Volumes are destroyed (**Rule 100147**).

---
## Incident Response Guidance
1.  **Level 12+ Alerts:** Immediate investigation required. Check `docker.Actor.Attributes.name` and logs for the container in question.
2.  **OOM Alerts (Rule 100111):** Review resource limits in `docker-compose.yml` or K8s manifests.
3.  **Shell Access (Rule 87907):** Verify if the access was authorized. Standard production containers should rarely have interactive shells.

---
## Technical Reference: Rule Definitions
Below are the raw XML definitions for the custom Docker rules.

```xml
<group name="docker_custom,container_security,">
  <!-- Fix lifecycle alerts so they match docker.Action -->
  <rule id="87903" level="5" overwrite="yes">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^start$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) started (image=$(docker.Actor.Attributes.image))</description>
    <group>docker,container_lifecycle,</group>
  </rule>

  <rule id="87904" level="7" overwrite="yes">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^stop$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) stopped</description>
    <group>docker,container_lifecycle,availability,</group>
  </rule>

  <rule id="87905" level="8" overwrite="yes">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^pause$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) paused</description>
    <group>docker,container_lifecycle,availability,</group>
  </rule>

  <rule id="87906" level="5" overwrite="yes">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^unpause$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) unpaused</description>
    <group>docker,container_lifecycle,</group>
  </rule>

  <!-- Important operational / suspicious container actions -->
  <rule id="100100" level="9">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^restart$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) restarted</description>
    <group>docker,container_lifecycle,availability,</group>
  </rule>

  <rule id="100101" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^(kill|die)$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) terminated. Action=$(docker.Action)</description>
    <group>docker,container_termination,availability,</group>
  </rule>

  <rule id="87907" level="12" overwrite="yes">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^exec_start:\s+(bash|/bin/bash|sh|dash|/bin/dash)$</field>
    <description>Docker: Interactive shell started in container $(docker.Actor.Attributes.name)</description>
    <group>docker,container_exec,suspicious_activity,</group>
  </rule>

  <rule id="100102" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^exec_start:\s+.+$</field>
    <field name="docker.Action" type="pcre2" negate="yes">^exec_start:\s+(bash|/bin/bash|sh|dash|/bin/dash)$</field>
    <description>Docker: Command executed in container $(docker.Actor.Attributes.name). Action=$(docker.Action)</description>
    <group>docker,container_exec,</group>
  </rule>

  <rule id="100103" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^extract-to-dir$</field>
    <description>Docker: File copied from host into container $(docker.Actor.Attributes.name)</description>
    <group>docker,file_transfer,</group>
  </rule>

  <rule id="100104" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^archive-path$</field>
    <description>Docker: File copied from container $(docker.Actor.Attributes.name) to host</description>
    <group>docker,file_transfer,data_egress,</group>
  </rule>

  <rule id="100105" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^export$</field>
    <description>Docker: Filesystem of container $(docker.Actor.Attributes.name) exported</description>
    <group>docker,data_egress,</group>
  </rule>

  <rule id="100106" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^image$</field>
    <field name="docker.Action" type="pcre2">^(save|push)$</field>
    <description>Docker: Image action detected. Action=$(docker.Action) Target=$(docker.Actor.Attributes.name)</description>
    <group>docker,image_activity,data_egress,</group>
  </rule>

  <rule id="100107" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^update$</field>
    <description>Docker: Container configuration updated for $(docker.Actor.Attributes.name)</description>
    <group>docker,configuration_change,</group>
  </rule>

  <rule id="100108" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^network$</field>
    <field name="docker.Action" type="pcre2">^(disconnect|destroy)$</field>
    <description>Docker: Network changed. Action=$(docker.Action) Network=$(docker.Actor.Attributes.name)</description>
    <group>docker,network_change,</group>
  </rule>

  <rule id="100109" level="12">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^secret$</field>
    <field name="docker.Action">^remove$</field>
    <description>Docker: Secret removed - $(docker.Actor.Attributes.name)</description>
    <group>docker,secrets,configuration_change,</group>
  </rule>

  <rule id="100110" level="9">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^config$</field>
    <field name="docker.Action">^remove$</field>
    <description>Docker: Config removed - $(docker.Actor.Attributes.name)</description>
    <group>docker,configuration_change,</group>
  </rule>

  <rule id="100111" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^oom$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) hit an OOM condition</description>
    <group>docker,resource_abuse,availability,</group>
  </rule>

  <!-- Correlation rules -->
  <rule id="100112" level="12" frequency="3" timeframe="300" ignore="300">
    <if_matched_sid>100100</if_matched_sid>
    <same_field>docker.Actor.Attributes.name</same_field>
    <description>Docker: Container $(docker.Actor.Attributes.name) restarted 3 times in 5 minutes</description>
    <group>docker,availability,incident,</group>
  </rule>

  <rule id="100113" level="13" frequency="3" timeframe="600" ignore="600">
    <if_matched_sid>87907</if_matched_sid>
    <same_field>docker.Actor.Attributes.name</same_field>
    <description>Docker: Multiple shell sessions started in container $(docker.Actor.Attributes.name)</description>
    <group>docker,container_exec,incident,</group>
  </rule>
</group>

<group name="docker_noise_reduction,container_security,">
  <!-- 1) Silence routine lifecycle noise for known safe containers -->
  <rule id="100120" level="0">
    <if_sid>87903</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(nginx-proxy|traefik|node-exporter|cadvisor|portainer|watchtower)$</field>
    <description>Docker noise reduction: known infrastructure container start</description>
  </rule>

  <rule id="100121" level="0">
    <if_sid>87904</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(nginx-proxy|traefik|node-exporter|cadvisor|portainer|watchtower)$</field>
    <description>Docker noise reduction: known infrastructure container stop</description>
  </rule>

  <rule id="100122" level="0">
    <if_sid>87905</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(nginx-proxy|traefik|node-exporter|cadvisor|portainer|watchtower)$</field>
    <description>Docker noise reduction: known infrastructure container pause</description>
  </rule>

  <rule id="100123" level="0">
    <if_sid>87906</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(nginx-proxy|traefik|node-exporter|cadvisor|portainer|watchtower)$</field>
    <description>Docker noise reduction: known infrastructure container unpause</description>
  </rule>

  <!-- 2) Silence routine starts from known images -->
  <rule id="100124" level="0">
    <if_sid>87903</if_sid>
    <field name="docker.Actor.Attributes.image" type="pcre2">^(prom/|grafana/|traefik|portainer/|gcr\.io/cadvisor|containrrr/watchtower)</field>
    <description>Docker noise reduction: known image start event</description>
  </rule>

  <!-- 3) Suppress healthcheck "healthy" chatter, but keep unhealthy visible -->
  <rule id="100125" level="0">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^health_status:\s+healthy$</field>
    <description>Docker noise reduction: healthy status event</description>
  </rule>

  <rule id="100126" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^health_status:\s+unhealthy$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) became unhealthy</description>
    <group>docker,availability,healthcheck,</group>
  </rule>

  <!-- 4) Silence expected execs used by automation -->
  <rule id="100127" level="0">
    <if_sid>100102</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(backup|db-migrate|certbot|watchtower)$</field>
    <description>Docker noise reduction: expected automated exec in approved container</description>
  </rule>

  <rule id="100128" level="0">
    <if_sid>100102</if_sid>
    <field name="docker.Action" type="pcre2">^exec_start:\s+(true|/bin/true|echo|/bin/sh -c echo .+)$</field>
    <description>Docker noise reduction: trivial exec command</description>
  </rule>

  <!-- 5) Silence routine network connect/disconnect for ephemeral workloads -->
  <rule id="100129" level="0">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^network$</field>
    <field name="docker.Action" type="pcre2">^(connect|disconnect)$</field>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(bridge|host|none|frontend|backend|monitoring)$</field>
    <description>Docker noise reduction: routine network attach/detach</description>
  </rule>

  <!-- 6) Suppress expected image pulls from CI/CD or auto-updaters -->
  <rule id="100130" level="0">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^image$</field>
    <field name="docker.Action">^pull$</field>
    <description>Docker noise reduction: routine image pull</description>
  </rule>

  <!-- 7) Keep restarts quiet individually, but still detect restart storms -->
  <rule id="100131" level="1" noalert="1" ignore="60">
    <if_sid>100100</if_sid>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(nginx-proxy|traefik|watchtower|backup)$</field>
    <description>Docker noise reduction: low-signal restart for approved container</description>
    <options>no_log</options>
  </rule>

  <rule id="100132" level="12" frequency="5" timeframe="600" ignore="300">
    <if_matched_sid>100131</if_matched_sid>
    <same_field>docker.Actor.Attributes.name</same_field>
    <description>Docker: Approved container $(docker.Actor.Attributes.name) restarted 5 times in 10 minutes</description>
    <group>docker,availability,incident,</group>
  </rule>

  <!-- 8) Optional: silence noisy create/destroy churn from ephemeral jobs -->
  <rule id="100133" level="0">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action" type="pcre2">^(create|destroy)$</field>
    <field name="docker.Actor.Attributes.name" type="pcre2">^(job-|runner-|build-|test-).*</field>
    <description>Docker noise reduction: ephemeral CI job lifecycle</description>
  </rule>
</group>

<group name="docker_additional_high_value,container_security,">
  <!-- Interactive access to a running container -->
  <rule id="100140" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^attach$</field>
    <description>Docker: Interactive attach to container $(docker.Actor.Attributes.name)</description>
    <group>docker,container_access,suspicious_activity,</group>
  </rule>

  <!-- Persistence / evidence destruction / image creation from live container -->
  <rule id="100141" level="12">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^commit$</field>
    <description>Docker: Container $(docker.Actor.Attributes.name) committed to a new image</description>
    <group>docker,persistence,image_activity,</group>
  </rule>

  <!-- Renaming can be used to hide or blend in -->
  <rule id="100142" level="9">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^container$</field>
    <field name="docker.Action">^rename$</field>
    <description>Docker: Container renamed - $(docker.Actor.Attributes.name)</description>
    <group>docker,configuration_change,evasion,</group>
  </rule>

  <!-- Image tampering / cleanup / staging -->
  <rule id="100143" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^image$</field>
    <field name="docker.Action" type="pcre2">^(delete|untag)$</field>
    <description>Docker: Image removed or untagged - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,image_activity,defense_evasion,</group>
  </rule>

  <rule id="100144" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^image$</field>
    <field name="docker.Action" type="pcre2">^(load|import|tag)$</field>
    <description>Docker: Image staged locally - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,image_activity,supply_chain,</group>
  </rule>

  <!-- Plugin changes are high-risk control-plane changes -->
  <rule id="100145" level="12">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^plugin$</field>
    <field name="docker.Action" type="pcre2">^(install|enable|disable|remove)$</field>
    <description>Docker: Plugin change detected - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,plugin_change,configuration_change,</group>
  </rule>

  <!-- Daemon reload usually means config changed or policy changed -->
  <rule id="100146" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^daemon$</field>
    <field name="docker.Action">^reload$</field>
    <description>Docker: Daemon reloaded configuration</description>
    <group>docker,daemon_change,configuration_change,</group>
  </rule>

  <!-- Persistent data destruction -->
  <rule id="100147" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^volume$</field>
    <field name="docker.Action">^destroy$</field>
    <description>Docker: Volume destroyed - $(docker.Actor.Attributes.name)</description>
    <group>docker,storage_change,impact,</group>
  </rule>

  <!-- Swarm-only: service changes -->
  <rule id="100148" level="11">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^service$</field>
    <field name="docker.Action" type="pcre2">^(create|update|remove)$</field>
    <description>Docker: Swarm service changed - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,swarm,configuration_change,</group>
  </rule>

  <!-- Swarm-only: node changes -->
  <rule id="100149" level="12">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^node$</field>
    <field name="docker.Action" type="pcre2">^(create|update|remove)$</field>
    <description>Docker: Swarm node changed - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,swarm,cluster_change,</group>
  </rule>

  <!-- Secrets are especially sensitive -->
  <rule id="100150" level="13">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^secret$</field>
    <field name="docker.Action" type="pcre2">^(create|update)$</field>
    <description>Docker: Secret changed - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,secrets,configuration_change,</group>
  </rule>

  <!-- Configs matter too, but are usually a bit less severe than secrets -->
  <rule id="100151" level="10">
    <if_sid>87900</if_sid>
    <field name="docker.Type">^config$</field>
    <field name="docker.Action" type="pcre2">^(create|update)$</field>
    <description>Docker: Config changed - $(docker.Actor.Attributes.name) (action=$(docker.Action))</description>
    <group>docker,configuration_change,</group>
  </rule>
</group>
```
