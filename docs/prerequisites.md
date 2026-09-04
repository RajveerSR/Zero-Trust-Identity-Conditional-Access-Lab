# Prerequisites and go/no-go gates

Do not deploy from the example manifests. No gate may be inferred from a successful local test.

## Licensing and roles

- Conditional Access requires Microsoft Entra ID P1 for in-scope users (or a qualifying suite such as Microsoft 365 Business Premium). Risk-based policies would require P2, but are out of scope.
- The device scenario additionally needs appropriate Microsoft Intune licensing for the users/devices and an assigned device-compliance policy.
- Reading policies through Microsoft Graph needs `Policy.Read.All`. Creating/updating needs both `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`; for delegated access, use a supported role such as Conditional Access Administrator (or Security Administrator). Use an eligible/temporary role where available.
- Sign-in collection needs `AuditLog.Read.All`; Conditional Access details also require a supported Conditional Access read permission/role. Reports Reader can read sign-ins, while Security Reader is a useful least-privileged choice when CA detail is required.
- The workload Bicep deployment needs resource-creation rights on the chosen resource group and permission to create the container-scoped role assignment (for example, a suitable RBAC administration role). Attaching the user-assigned identity to a host needs the corresponding managed-identity assignment permission.

## Shared-identity coordination gate

The Enterprise Identity Governance Lab is the system of record for ordinary users, admin personas, emergency accounts, and their groups. Before any deployment:

- Copy its real non-secret object IDs into ignored `config/lab-identities.json`.
- Confirm the ordinary-user and administrator group memberships directly in the tenant.
- Confirm there are at least two cloud-only emergency accounts and a dedicated emergency-access group. Coordinate provisioning there; do not create substitutes here.
- Confirm emergency credentials use an independently resilient, phishing-resistant method, are securely stored, monitored, and tested at least every 90 days.
- Create a shared change record containing tenant ID, affected group/app IDs, planned window, owners, other repository changes, rollback owner, and evidence location.
- Review all existing tenant Conditional Access and authentication-method policies. A separate repository does not isolate tenant effects.

## Authentication gate

- Pilot ordinary users have at least one permitted MFA method registered.
- Pilot administrators have a phishing-resistant method enabled and successfully tested before CA002 is enabled. Prefer two independently recoverable credentials where practical.
- Query/inspect the tenant's authentication-strength policies and verify that `PHISHING_RESISTANT_AUTH_STRENGTH_ID` resolves to the intended built-in strength. The example currently uses `00000000-0000-0000-0000-000000000004`, but tenant verification is still a gate.

## Device gate

CA003 must remain labelled **designed but unverified** unless every item below is evidenced:

- Test user has the required Entra ID and Intune licensing.
- A Windows Intune compliance policy is assigned to the v0.1 pilot.
- Test device is registered with Microsoft Entra ID, enrolled in Intune, and has completed a recent compliance check.
- At least one compliant and one deliberately noncompliant/unknown Windows test state is available without risking a production device.
- The chosen browser/client supports device identity presentation. Private browsing and unsupported browser/platform combinations can cause an otherwise managed device to appear unknown.
- `SENSITIVE_APP_ID` is the application (client) ID Microsoft Entra evaluates as the target resource, confirmed from the intended enterprise application's sign-in/resource context; it is not the service-principal object ID.

Microsoft's current guidance warns that a compliant-device Conditional Access policy does not work as intended without an Intune compliance policy and at least one compliant device.

## Workload gate and costs

The optional workload demonstration creates a Standard LRS Storage account, two private containers, a user-assigned managed identity, and one Azure role assignment. Storage capacity and transactions are chargeable; the Azure compute host used to run the identity probe may also be chargeable. Set a budget/expiry, use an existing suitable host if available, and remove the resource group after evidence capture.

The template leaves the Storage public endpoint enabled because no host network is known during scaffolding. Shared-key access and anonymous Blob access are disabled. Before production-like use, constrain network access to the selected host path.

## Authoritative references checked 4 September 2026

- [Conditional Access overview and licensing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Require device compliance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance)
- [Conditional Access grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)
- [Authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [Conditional Access report-only mode](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
- [Create Conditional Access policy through Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0)
- [List sign-ins through Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
- [Manage emergency-access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
