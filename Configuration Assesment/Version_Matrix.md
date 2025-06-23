## Wazuh SCA OS Support Timeline

### **Wazuh 4.7.4** – released 29 April 2024 ([documentation.wazuh.com][1])

Included all baseline SCA policy files for these OS versions (as listed in SCA policy catalog):

* **Windows**: Win 10, Win 11, Server 2012 (non‑R2 & R2), 2016, 2019, 2022
* **Linux**: Alma/Rocky/Oracle/CentOS/RHEL 5–10; Debian 7–12; Ubuntu 14.04–22.04; Amazon Linux 1, 2, 2023; SUSE SLES 11–15; Solaris 11/11.4; HP‑UX 11i ([github.com][2], [documentation.wazuh.com][3])
* **macOS**: macOS 10.11 → 14.x (El Capitan through Sonoma) ([documentation.wazuh.com][3])

---

### **Wazuh 4.7.5 → 4.11.2** – May 2024 through April 2025&#x20;

These were minor/cumulative releases that **retained support** for the same OS versions introduced in 4.7.4. No new SCA policies for additional OS versions were added during this period.

---

### **Wazuh 4.12.0** – released 7 May 2025 ([documentation.wazuh.com][4])

**Newly added SCA support** in this release:

* **Windows**: **Server 2025** (via `cis_win2025.yml`) ([documentation.wazuh.com][3])
* **Linux**: **Ubuntu 24.04 LTS** (via `cis_ubuntu24-04.yml`) and **generic distribution‑independent policy** ([documentation.wazuh.com][3])
* **macOS**: **macOS 15.x (Sequoia)** support (via `cis_apple_macOS_15.x.yml`) ([documentation.wazuh.com][3])

All previous SCA policies (e.g. Windows 10/11, Ubuntu 22.04, macOS 14.x, etc.) continued to be supported alongside the new additions.

---

## Summary Matrix

| **Wazuh Version**  | **Windows** (SCA)                       | **Linux** (SCA)                                                                                                                    | **macOS** (SCA) |
| ------------------ | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| **4.7.4**          | 10, 11, 2012, 2012 R2, 2016, 2019, 2022 | Alma/Rocky/Oracle/CentOS 5–10, Debian 7–12, Ubuntu 14.04–22.04, Amazon Linux 1/2/2023, SUSE SLES 11–15, Solaris 11/11.4, HP‑UX 11i | 10.11–14.x      |
| **4.7.5 → 4.11.2** | Same as 4.7.4                           | Same as 4.7.4                                                                                                                      | Same as 4.7.4   |
| **4.12.0**         | +Server 2025                            | +Ubuntu 24.04 LTS & distro‑independent policy                                                                                      | +macOS 15.x     |

---

[1]: https://documentation.wazuh.com/current/release-notes/release-4-7-4.html?utm_source=chatgpt.com "4.7.4 Release notes - 29 April 2024 - 4.x - Wazuh"
[2]: https://github.com/wazuh/wazuh/issues/28508?utm_source=chatgpt.com "SCA maintenance monthly check - March 2025 #28508 - GitHub"
[3]: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/available-sca-policies.html?utm_source=chatgpt.com "Available SCA policies - Security Configuration Assessment - Wazuh"
[4]: https://documentation.wazuh.com/current/release-notes/release-4-12-0.html?utm_source=chatgpt.com "4.12.0 Release notes - 7 May 2025 - 4.x · Wazuh documentation"
[5]: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-to-configure.html?utm_source=chatgpt.com "How to configure SCA - Security Configuration Assessment - Wazuh"
[6]: https://github.com/wazuh/wazuh/issues/29297?utm_source=chatgpt.com "Release 4.12.0 - Beta 1 - Footprint Metrics - SCA (2.5d) #29297"
