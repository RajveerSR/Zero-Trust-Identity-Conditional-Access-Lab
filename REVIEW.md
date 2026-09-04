# Claude Code verification handoff

## Review state

The repository is ready for independent local verification and subsequent Microsoft account/tenant setup. It is **not tenant-verified**. No Microsoft sign-in, consent, Graph tenant read/write, Conditional Access deployment, What If evaluation, Intune operation, Azure deployment, or chargeable-resource creation occurred in this pass.

The initial scaffold is preserved in baseline commit `017e546`. Follow-up implementation commits are:

- `84a60db` — resolved Windows Azure CLI execution, safe JSON payload transport, and Graph failure/pagination tests.
- `85585a6` — tenant-bound policy identity records and exact ownership checks for enable/disable.
- `198eb9a` — report-only deployment guards, realistic drift tests, partial-progress reporting, and workload-denial classification.

## Implemented behaviour

Three Conditional Access pilots remain version-controlled in `enabledForReportingButNotEnforced`: baseline MFA, phishing-resistant authentication for the lab-admin pilot, and compliant Windows access to one sensitive application. CA002's `All` application scope includes Azure management, CLI, and PowerShell access for pilot administrators.

The Python tooling now:

- resolves and executes the discovered Azure CLI path, including Windows `az.cmd` paths containing spaces;
- transports Graph JSON bodies through a temporary payload file rather than a command-line JSON string;
- converts missing executables, process-launch failures, CLI failures, malformed JSON, and malformed collections into clear unsuccessful results;
- rejects example configuration, unresolved variables, wrong tenants, enabled-policy overwrite, hidden out-of-source settings, malformed current objects, and ambiguous duplicate display names before deployment writes;
- distinguishes supported server-added authentication-strength metadata from real strength/control drift;
- reports completed and last-attempted work after a partial multi-policy failure and explicitly requires a fresh export/preview rather than claiming rollback or atomicity;
- builds an ignored identity record from an exact postdeployment export and binds enable/disable to its tenant ID, repository policy key, Graph ID, and exact display name;
- prints the fetched target and intended state action before PATCH.

The workload probe now accepts the negative test only when the allowed container succeeds and the sibling-container failure is classified as authorization. Network, authentication, missing-resource, and unknown failures fail the demonstration. Real host selection and inherited-role review remain Azure-dependent.

## Local verification run on 4 September 2026

| Check | Result |
|---|---|
| `python scripts/validate_policies.py --use-example-config` | Pass: 3 report-only definitions |
| `python scripts/preview_changes.py --use-example-config --current tests/fixtures/current-policies.json` | Pass: synthetic CA001 `UPDATE`, CA002 `UNCHANGED`, CA003 `CREATE` |
| `python -m unittest discover -s tests -v` | Pass: 51 tests; no network calls |
| `powershell.exe -NoProfile -File tests/Test-PowerShellSyntax.ps1 -Path scripts/Test-WorkloadIdentity.ps1` | Pass |
| `powershell.exe -NoProfile -File tests/Test-PowerShellSyntax.ps1 -Path src/WorkloadProbe.psm1` | Pass |
| `powershell.exe -NoProfile -File tests/Test-WorkloadProbeClassification.ps1` | Pass: 7 diagnostic cases |
| `az bicep build --file infra/workload-identity.bicep --stdout` | Pass with Bicep 0.46.1; compilation only |
| `git diff --check` | Pass |

The checked-in current-policy fixtures and preview are synthetic. Local mocks prove which Graph method, endpoint, and payload would be selected; they do not prove tenant permissions, service acceptance, evaluation, or enforcement.

## Microsoft/tenant setup prerequisites

Do not assume Microsoft developer-program eligibility or trial availability. Confirm the actual tenant and licences before scheduling tenant work.

1. Establish the Microsoft Entra tenant and a tested administrative/recovery path.
2. Confirm Microsoft Entra ID P1 or a qualifying licence for every in-scope Conditional Access user. Confirm Intune entitlement separately before treating CA003 as runnable.
3. Provision/reconcile shared lab users, groups, and at least two emergency-access accounts through the Enterprise Identity Governance Lab. This repository must not create competing identities.
4. Populate ignored `config/lab-identities.json` and `config/tenant.json`; confirm group memberships, tenant ID, sensitive resource application ID, and existing tenant policies.
5. Enable and register ordinary MFA methods and phishing-resistant methods for pilot admins before CA002 enforcement. The phishing-resistant strength ID is a Microsoft built-in constant; verify its resolved definition and enabled methods rather than replacing it as though tenant-specific.
6. Obtain the least-privileged role/scopes for each operation: policy reads first, policy write only for the approved report-only change, and sign-in-log/CA detail read permissions only for evidence collection.
7. For CA003, obtain Intune licensing, an assigned Windows compliance policy, an enrolled test device, and both compliant and noncompliant/unknown controlled states.
8. For the workload, separately approve subscription/resource group, cost/budget, host, network path, RBAC administration rights, and cleanup.

## Operation boundaries after account setup

| Stage | Cloud effect | Required output before proceeding |
|---|---|---|
| Local validation and fixture preview | None | Passing local checks |
| Policy export | Read-only tenant access | Tenant-bound prechange export reviewed for existing interactions and duplicates |
| Preview against export | None; snapshot can become stale | Exact create/update/no-change review |
| Report-only deployment | **Writes tenant configuration**; does not enforce grant controls | Postdeployment export proving report-only state |
| Policy identity-record build | Local file write only | Exact one-to-one policy key/name/ID/tenant bindings |
| What If | Tenant simulation/read activity | Inputs and applicable/nonapplicable policy evidence |
| Report-only sign-ins | Real sign-ins; new lab policies do not enforce | Per-policy report-only outcomes, correctly labelled |
| Enable one policy | **Enforcement-changing tenant write** | Approval, recovery coverage, then actual enforced sign-ins |
| Intune/device testing | Tenant/device-management changes and real device state | Correlated Intune and sign-in evidence |
| Workload deployment/probe | Azure writes and potentially chargeable resources | What If, deployment/RBAC export, allowed plus authorization-denied evidence, cleanup |

## Known limitations

- Real IDs, group membership, licences, roles/scopes, authentication-method state, and existing tenant-policy interactions are unknown.
- Azure CLI delegated Graph authorization still depends on the future tenant's consent and operator role; offline tests only prove local command construction and failure handling.
- Local validation enforces the repository contract, not the complete evolving Microsoft Graph service schema.
- CA002 deliberately uses a pilot group and does not claim coverage of every privileged directory role.
- CA003 remains designed but unverified until both compliant and negative Windows device cases are correlated with Intune and sign-in evidence.
- The workload remains designed but unverified. The Storage public endpoint is enabled pending host/network selection, and inherited RBAC assignments have not been inspected.
- Failure-category matching is a guardrail, not sufficient evidence by itself; reviewers must retain the real Azure error and scope/identity records.
- No automated Graph What If client is included; the tenant matrix uses the current portal/API workflow and manual capture.

## Focused Claude review checklist

1. Verify `src/graph_cli.py` safely executes the resolved Windows command path and that `@payload-file` transport is accepted by the installed Azure CLI without exposing JSON or tokens.
2. Attempt offline bypasses of policy identity binding: wrong tenant, key, ID, exact display name, source definition, state, confirmation, malformed GET response, and example record.
3. Confirm every refusal test makes zero POST/PATCH/DELETE calls and the valid paths address only the expected policy endpoint/payload.
4. Review `normalize_graph_policy` against a representative real Graph export: read-only authentication-strength metadata should disappear, while a changed strength ID or writable control must remain drift.
5. Confirm duplicate display names fail preview, identity-record creation, and deployment rather than selecting one arbitrarily.
6. Review partial-deployment messaging for first-write success/second-write failure and uncertain POST response; it must not imply transactionality or rollback.
7. Challenge workload classification with real Azure CLI diagnostics and confirm missing container, authentication, network, and unknown errors cannot satisfy the denied test.
8. Reassess policy interactions and lockout blast radius, especially CA002 coverage of Azure management/CLI and the emergency-access dependency.
9. Confirm the evidence taxonomy still separates local source checks, What If, report-only evaluation, and actual enforced sign-ins.
