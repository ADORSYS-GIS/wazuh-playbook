# Wazuh Cluster Upgrade Playbook (Kubernetes)

**Objective**: Safely upgrade Wazuh components (Indexer, Dashboard, Manager) deployed in Kubernetes with minimal downtime.

---

## Prerequisites

1. **Compatibility Check**
   - Confirm that your Kubernetes version is compatible with the target Wazuh version.
   - Review the [Wazuh Upgrade Guide](https://documentation.wazuh.com/current/installation-guide/upgrading/index.html) for version-specific changes.

2. **Maintenance Window**  
   Perform upgrades during scheduled low-traffic periods.

---

## Upgrade Steps

### 1. Upgrade the [WAZUH-HELM](https://github.com/ADORSYS-GIS/wazuh-helm) Repository

**Goal**: Update the Helm chart to reflect the desired Wazuh version.

- **Update `global.version`**

  Modify the `global.version` field in `charts/wazuh/values.yaml` to the target Wazuh version.

  ![Example of version update](image.png)

- **Apply Configuration Changes**

  Review and apply changes from the `CHANGELOG.md` of the [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) repository.

  Example for version **v4.11.1**:  
  [CHANGELOG](https://github.com/wazuh/wazuh-kubernetes/blob/v4.11.1/CHANGELOG.md)

  - If you're upgrading from **v4.11.0** -> **v4.11.1**, no configuration changes are required.

  - Upgrading from older versions (e.g., **v4.10.0**) might require config changes:  
    ![Configuration change example](image-2.png)

- **Update Helm Chart Metadata**

  In `charts/wazuh/Chart.yaml`:
  - Increment the `version` (Helm chart version).
  - Set `appVersion` to the new Wazuh version.

  Commit and push your changes. This triggers a GitHub Action to publish a new release, named after the `appVersion`.

---

### 2. Upgrade the [WAZUH](https://github.com/ADORSYS-GIS/wazuh) Repository

**Goal**: Point Argo CD to the updated Helm release.

This repo contains Argo CD configs that deploy Wazuh in both `dev` and `prod` clusters via GitOps. Updates must be reflected accordingly:

- **Dev Cluster Update**
  - On the `develop` branch, update the `targetRevision` for the Wazuh application in `charts/argocd-apps/values-dev.yaml`.
  - Set the value to match the new Helm release version.

    ![Dev cluster update](image-3.png)

- **Prod Cluster Update**
  - On the `main` branch, update the `targetRevision` in `charts/argocd-apps/values-prod.yaml`.
  - Again, use the same Helm release version.

    ![Prod cluster update](image-5.png)
    
Commit and push your changes. This triggers a GitHub Action to publish a new helm release using ARGO CD in our infrastructure.

---

## Best Practices

- **Test in `dev`**  
  Always validate the upgrade in the `dev` cluster for **at least one day** before promoting to `prod`.

---

## Post-Upgrade Validation

- **Dashboard**: Confirm that all visualizations and dashboards load correctly.
- **Manager**: Check agent connectivity via the UI or API.
