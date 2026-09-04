# Threat model

## Organisation and assets

Fabrikam Research is a fictional small organisation with ordinary staff, a small administrator team, managed and unmanaged endpoints, one sensitive enterprise application, and a limited Azure workload. Shared users and groups are provisioned by the separate Enterprise Identity Governance Lab; this repository consumes their non-secret object IDs and owns only Conditional Access policy definitions and the workload demonstration.

The assets are tenant administration, ordinary user accounts, sensitive-app data, Conditional Access configuration, emergency recovery capability, sign-in evidence, and the workload's Blob data.

## Trust boundaries

1. A human and their authenticator cross from an untrusted network/client into Microsoft Entra authentication.
2. Entra evaluates identity, target resource, client, and device signals against all applicable policies.
3. Intune supplies compliance state; a registered device without a valid compliance signal is not assumed healthy.
4. The managed identity obtains a token from the Azure host rather than storing a credential.
5. Azure RBAC authorizes that workload token at one Blob-container scope.
6. Microsoft Graph exports tenant configuration and sign-in observations into the local evidence boundary.

## Threats and treatments

| Threat | Likely path | Treatment in v0.1 | Residual risk / next control |
|---|---|---|---|
| Stolen user password | Password reuse or phishing | CA001 requires MFA for pilot groups | MFA fatigue and token theft remain; tune methods and session controls later |
| Privileged phishing | Adversary-in-the-middle captures password and weak MFA | CA002 requires phishing-resistant authentication strength | Admin device/session compromise remains; use privileged workstations and PIM in a broader design |
| Sensitive data from unmanaged device | Valid user authenticates from unknown or unhealthy endpoint | CA003 requires compliant device for one app | Compliance is a point-in-time signal, not proof a device is uncompromised |
| Administrative lockout | Bad scope, missing method, broken device signal | Pilot groups, report-only rollout, emergency exclusions, separate enable action | Emergency accounts are powerful bypasses and require monitoring and drills |
| Exception becomes permanent bypass | Broad or forgotten exclusion membership | Named per-control exception groups; require owner, expiry, and review outside policy JSON | Governance process must actually remove expired members |
| Workload credential theft | Secret committed or copied | User-assigned managed identity; no secret in repository | Azure host compromise can use its identity while attached |
| Excessive workload access | Broad subscription/storage role | Blob Data Reader at one `allowed` container; negative test against sibling container | Public Storage endpoint remains enabled until an available host network is selected |
| Misleading evidence | Report-only result presented as enforced block | Evidence taxonomy and metadata distinguish preview, What If, report-only, and enforced sign-ins | Human review is still required before interview/public use |

## Out of scope

Risk-based P2 policies, broad legacy-auth blocking, custom identity providers, dashboards, session-control tuning, Defender integration, enterprise-wide deployment, and workload-identity Conditional Access are intentionally deferred. Human MFA policies do not apply to managed identities or service principals.

## Assumptions to test

- Group membership is current and nested-group behaviour is understood before testing.
- The sensitive resource ID is the resource/service principal users actually request, not merely an app registration object copied by name.
- Authentication methods accepted by the built-in strength are enabled and registered before CA002 enforcement.
- CA002's `All` resource scope includes Azure management, CLI, and PowerShell sign-in paths for pilot admins; test those paths before enforcement rather than treating the policy as portal-only.
- Intune has evaluated the Windows test device recently and the chosen client presents its device identity. Other platforms are outside the v0.1 device pilot.
- Existing tenant policies can interact with these policies; this repository never assumes an isolated tenant.
