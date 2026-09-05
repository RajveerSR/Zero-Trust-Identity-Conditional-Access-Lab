# Zero Trust Identity & Conditional Access Lab

A small, version-controlled Microsoft Entra lab for designing, previewing, testing, and troubleshooting Conditional Access without confusing **report-only evaluation** with enforcement. It is aimed at an interview demonstration and SC-300 practice.

## Current status

CA001 and CA002 are deployed and verified in **report-only mode**. The Entra portal shows **Report-only: Success** for both, and three live What If evaluations confirm the intended user scopes. The offline Python suite passes 67 tests.

The [observed evidence pack](evidence/observed/2026-09-05/README.md) contains the supplied portal screenshots, redacted Graph readback and simulation results. **Enforcement, device compliance, recovery drills and the Azure workload are still unverified.**

| Capability | State | Verification boundary |
|---|---|---|
| Baseline MFA for shared lab users/admins | Deployed report-only | Exact readback, portal report-only success and What If |
| Phishing-resistant authentication for lab admins | Deployed report-only | Same; fresh method-specific passkey event not captured |
| Compliant Windows device for the sensitive app | Prepared, not deployed | Verified Azure Resource Manager target; Intune/device evidence pending |
| Report-only Graph deployment | Live verified for CA001/CA002 | No enforcement enabled |
| Managed identity to one Blob container | Designed, unverified | No Azure resources deployed; host and spending decision pending |

![Two policies evaluated successfully in Entra report-only mode](evidence/observed/2026-09-05/report-only-success.png)

## Interview walkthrough

1. Explain the shared identity boundary and why privileged users need a stronger authentication requirement.
2. Show the source policies and guarded preview/apply separation.
3. Open the evidence pack: configuration readback, the three applicability simulations and the report-only screenshot.
4. Explain the troubleshooting finding: the portal exposes results missing from the CLI export; retain the real observation without inventing a machine-readable result.
5. State what is still untested, and show the recovery/enforcement and device test gates.

## Design

```mermaid
flowchart LR
  G[Shared lab identity manifest] --> MFA[CA001 baseline MFA]
  G --> ADM[CA002 admin phishing-resistant MFA]
  G --> DEV[CA003 compliant device]
  APP[Sensitive enterprise app] --> DEV
  INT[Intune compliance signal] --> DEV
  MI[User-assigned managed identity] -->|Blob Data Reader: allowed container only| OK[allowed container]
  MI -. expected denial .-> NO[denied container]
```

Policy interaction is intentional: a lab administrator accessing the sensitive app must satisfy both CA002's phishing-resistant authentication strength and CA003's compliant-device control. CA001 also applies, but a phishing-resistant MFA method satisfies its ordinary MFA requirement. Emergency access is excluded from all three definitions so recovery does not depend on the controls being repaired.

## Repository map

- `policies/` — deployable Microsoft Graph policy bodies wrapped with review metadata.
- `config/` — non-secret example identifiers and deployment settings. The identity manifest points back to the Enterprise Identity Governance Lab as system of record.
- `src/` — dependency-free policy loading, substitution, comparison, and validation.
- `scripts/` — local preview, guarded Graph deployment/export, evidence collection, and workload probe.
- `tests/` — Python unit tests, fixtures, and the tenant test matrix.
- `docs/` — threat model, policy rationale, prerequisites, rollout, troubleshooting, and recovery.
- `evidence/` — evidence index, completion checklist, and synthetic examples.
- `learning/` — SC-300 mapping and original practice scenarios.
- `infra/` — optional Bicep for the narrowly scoped workload-identity resources.

## Quick start

Requirements for local-only work: Python 3.10+ and no third-party packages.

```powershell
python scripts/validate_policies.py --use-example-config
python scripts/preview_changes.py --use-example-config --current tests/fixtures/current-policies.json
python -m unittest discover -s tests -v
```

Before any tenant work:

1. Copy `config/lab-identities.example.json` to `config/lab-identities.json` and replace every example UUID with the existing shared-object IDs from the Enterprise Identity Governance Lab.
2. Copy `config/tenant.example.json` to `config/tenant.json`; confirm the sensitive resource's application (client) ID and the built-in authentication-strength ID in the target tenant.
3. Complete every prerequisite gate and record shared-tenant coordination in [docs/prerequisites.md](docs/prerequisites.md).
4. Export current policy state and preview. Only then use the separately guarded report-only apply command in [docs/rollout-and-recovery.md](docs/rollout-and-recovery.md).

Enabling a policy is deliberately a different script and requires a tenant-bound policy identity record plus a confirmation phrase containing the policy key and exact Graph ID. Report-only results are evaluation evidence; they are not proof that access was enforced, and creating a report-only policy is still a tenant configuration change.

## Security decisions to defend

- **Explicit pilot groups, not `All users`:** confines blast radius and makes the shared identity boundary visible. A production design should separately evaluate broad coverage gaps.
- **Two authentication levels:** baseline MFA reduces common account takeover; phishing-resistant MFA protects privileged activity from adversary-in-the-middle phishing and MFA fatigue.
- **One control per reason:** the Windows device control is a separate policy, so What If and sign-in logs show why a sign-in would be challenged or blocked. Other platforms are deferred to avoid known report-only certificate prompts without platform-specific testing.
- **Emergency-access design:** the source excludes a recovery group; the live group is currently empty because account setup was deferred. Monitoring and recovery drills are not yet demonstrated.
- **Human and workload identities are separate:** user MFA policies do not protect service principals. The workload demo uses Azure RBAC and a managed identity with container-scoped read access.
- **Fail-safe rollout:** definitions can only deploy in `enabledForReportingButNotEnforced`; enforcement requires a separate reviewed action after successful tenant tests.

See [REVIEW.md](REVIEW.md) for the independent-review handoff and [evidence/completion-checklist.md](evidence/completion-checklist.md) for the demonstrable path.
