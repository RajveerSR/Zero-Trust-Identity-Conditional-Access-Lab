# Claude Code review handoff

## Implementation summary

This first version defines three bounded Conditional Access pilots: baseline MFA for shared lab users/admins, phishing-resistant authentication for the lab-admin group, and compliant-device access to one sensitive application. Every policy is source-controlled in report-only state and includes rationale, scope, exclusions, prerequisites, controls, user impact, ownership, and verification status.

Dependency-free Python tooling validates invariants, substitutes non-secret object IDs, previews create/update/no-change against an export, deploys only report-only policies through Microsoft Graph, exports configuration, and collects data-minimised sign-in evidence. Mutating and evidence commands verify the Graph token tenant. Policy enabling and emergency disabling are separate, single-object, confirmation-guarded commands. Updates stop if a tenant object contains non-empty settings absent from source rather than risk retaining hidden drift through PATCH semantics.

The workload scenario uses a user-assigned managed identity and container-scoped Storage Blob Data Reader role. A host-side PowerShell probe expects success against `allowed` and authorization denial against `denied`. No Azure host is assumed or created.

## Tests run

- `python scripts/validate_policies.py --use-example-config`
- `python scripts/preview_changes.py --use-example-config --current tests/fixtures/current-policies.json`
- `python -m unittest discover -s tests -v`
- `powershell.exe -NoProfile -File tests/Test-PowerShellSyntax.ps1 -Path scripts/Test-WorkloadIdentity.ps1`
- `az bicep build --file infra/workload-identity.bicep --stdout`

All completed successfully on 4 September 2026. The fixture preview produced CA001 `UPDATE`, CA002 `UNCHANGED`, and CA003 `CREATE`; this is synthetic drift coverage, not tenant state.

No tenant, Microsoft Graph mutation, Intune action, Azure deployment, What If evaluation, or real sign-in test was run.

## Known limitations

- Real shared object IDs, group membership, target resource ID, authentication-strength lookup, licences, roles, and existing tenant-policy interactions are unknown.
- Azure CLI delegated Graph authorization varies with tenant consent/session; the scripts fail closed on API errors but require a suitably authorized operator.
- Local validation checks the project contract, not the complete evolving Microsoft Graph schema. Graph remains the service-side authority.
- CA002 uses a pilot admin group to limit blast radius; it does not claim coverage of every privileged directory role.
- CA003 is designed but unverified until Intune and supported-device prerequisites exist and both positive/negative cases are observed.
- The workload template enables the public Storage endpoint pending a real host/network selection. Shared-key and anonymous Blob access are disabled.
- The workload probe's denial must be reviewed to distinguish RBAC authorization from network or configuration failure.
- Evidence collection intentionally omits UPN, IP/location, and detailed authentication steps; a private incident investigation may need a separate access-controlled export.
- There is no automated Graph What If client; the test matrix uses the current portal/API workflow and manual capture.

## Review questions

1. Do all-policy interactions produce the intended effective AND across CA001/CA002/CA003, including existing tenant policies and resource dependencies?
2. Are the emergency exclusions, two-account requirements, authentication independence, monitoring, and disable path sufficient to control lockout risk?
3. Are `Policy.Read.All` + `Policy.ReadWrite.ConditionalAccess`, the supported delegated role, and `AuditLog.Read.All`/CA-read permissions correctly least-privileged for each operation?
4. Should the admin pilot remain group-scoped for v0.1, or should a later production variant target specific directory role template IDs after a broader lockout review?
5. Does `SENSITIVE_APP_ID` identify the actual resource evaluated in sign-in logs, and are service dependencies covered by the tenant test cases?
6. Is the device evidence strong enough to correlate Intune compliance time, device ID, client, resource, and sign-in result without overclaiming?
7. Does the managed-identity denial prove container-level least privilege, and are inherited RBAC assignments absent?
8. Is the collected/redacted evidence sufficient for an interviewer to distinguish source intent, simulation, report-only evaluation, and enforcement?
9. Does any existing work in the Enterprise Identity Governance Lab conflict with exception-group or emergency-access ownership described here?
