# Workload identity demonstration

## Scenario

A user-assigned managed identity is attached to an available Azure compute host. Azure RBAC grants **Storage Blob Data Reader** only at the `allowed` Blob-container scope. The same identity lists blobs in `allowed` successfully and receives an authorization failure for the sibling `denied` container.

This is deliberately a resource-authorization demonstration, not a human sign-in. No MFA claim is expected or useful for the managed identity. Current Conditional Access for workload identities targets eligible service principals and excludes managed identities, so it is not the control used here. The relevant controls are credential elimination, narrow RBAC scope, host attachment governance, logging, and lifecycle management.

## Resources and cost

`infra/workload-identity.bicep` creates one Standard LRS Storage account, two private containers, one user-assigned managed identity, and one role assignment. Storage capacity/transactions are chargeable. The chosen VM, App Service, Container Instance, or other compatible Azure host may be chargeable. No host is created because available infrastructure and network boundaries are not yet known.

Shared-key and anonymous Blob access are disabled. The public Storage endpoint remains enabled for this first design; constrain it after choosing the host network.

## Preview and deploy

Do not run during initial scaffolding. After selecting a subscription/resource group, checking budget, and obtaining approval:

```powershell
az deployment group what-if `
  --resource-group <resource-group> `
  --template-file infra/workload-identity.bicep `
  --parameters namePrefix=ztidlab

az deployment group create `
  --resource-group <resource-group> `
  --template-file infra/workload-identity.bicep `
  --parameters namePrefix=ztidlab
```

The operator needs resource deployment rights plus permission to create the RBAC assignment. Save the What If output and deployment outputs. Attach the output user-assigned identity to an existing suitable host through that host's normal configuration workflow.

RBAC propagation can take time. Avoid broadening scope while waiting; record the role assignment and retry after a controlled interval.

## Probe

Run this **on the Azure host with the identity attached**, using deployment outputs:

```powershell
./scripts/Test-WorkloadIdentity.ps1 `
  -ManagedIdentityClientId <client-id> `
  -StorageAccountName <storage-name> `
  -EvidencePath evidence/tenant/workload-probe.json
```

Expected evidence:

- `allowed`: exit code 0 and `allowed: true`.
- `denied`: nonzero exit code, `allowed: false`, and `failureCategory: authorization`.
- overall `passed: true` only when both positive and negative expectations hold.

The probe never records an access token or storage key. It classifies missing-resource, authentication, network, authorization, and unknown failures; only authorization is accepted as the negative RBAC result. A DNS timeout, failed managed-identity login, missing container, or unknown CLI error therefore fails the overall probe instead of becoming false least-privilege evidence.

Before accepting real evidence, also record the selected Azure host and export inherited role assignments at resource-group, storage-account, and container scopes. An inherited broad data role can invalidate the expected denial even when the template's direct assignment is narrow.

## Cleanup

Detach the identity from the host, preserve evidence and deployment metadata, and remove the dedicated resources/resource group through the approved Azure change process. Confirm the role assignment and identity are gone so an abandoned principal or chargeable resource does not remain.

References: [managed identities overview](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview), [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity), [assign Azure roles for Blob data](https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access), and [Storage Blob Data Reader definition](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage#storage-blob-data-reader).
