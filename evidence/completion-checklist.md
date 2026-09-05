# Capability-to-evidence completion checklist

## Local and design

- [x] Threats, identities, resources, boundaries, and residual risks documented â€” `docs/threat-model.md`.
- [x] Three minimal policy definitions include purpose, scope, exclusions, controls, prerequisites, impact, and status â€” `policies/*.json`.
- [x] Policy interaction and expected outcomes documented â€” `docs/policy-matrix.md`.
- [x] Local validation and deterministic tests implemented â€” `scripts/validate_policies.py`, `tests/test_ca_policy.py`.
- [x] Readable create/update/no-change preview implemented â€” `scripts/preview_changes.py`.
- [x] Report-only deployment guarded from example config and enabled state â€” `scripts/deploy_report_only.py`.
- [x] Report-only deployment guard branches, exact endpoints/payloads, partial failure, and no-write refusals have offline regression coverage.
- [x] Enforcement is a separate single-policy action bound to exact tenant/key/ID/name ownership â€” `scripts/enable_policy.py`.
- [x] Recovery uses the same exact ownership binding and remains independently invocable â€” `scripts/disable_policy.py`.
- [x] Windows `az.cmd` resolution, process errors, safe payload transport, malformed JSON, and pagination have offline tests.
- [x] Realistic server-added authentication-strength metadata and writable drift are tested separately.
- [x] Emergency exclusion, monitoring, drill, and recovery model documented â€” `docs/recovery-runbook.md`.
- [x] Shared identities consumed via an explicit non-secret manifest â€” `config/lab-identities.example.json`.
- [x] Managed-identity least-privilege scenario and positive/negative probe prepared â€” `infra/`, `docs/workload-identity.md`.
- [x] Negative workload diagnostics reject network, authentication, missing-resource, and unknown failures locally.
- [x] Local evidence is explicitly labelled synthetic â€” `evidence/examples/`.
- [x] Actual local regression evidence recorded separately from tenant evidence â€” `evidence/local/verification-2026-09-04.md`.

## Tenant-dependent Conditional Access

- [x] Shared user/group identifiers reconciled with the governance lab; recovery accounts still deferred.
- [x] Prechange export reviewed; two selected report-only policies created and exact IDs recorded.
- [x] CA001/CA002 postdeployment state, scopes and grant controls verified; identity record built for those two only.
- [x] Three live What If cases captured: administrator, ordinary user, disabled leaver.
- [x] Portal report-only successes captured for CA001/CA002; see limitations in the observed evidence pack.
- [ ] Resolve the CLI/portal evidence discrepancy and correlate the exact sign-in ID.
- [ ] Capture remaining applicable What If/sign-in matrix cases; three cases do not complete the full matrix.
- [ ] Establish and test recovery and monitoring before enforcement.
- [ ] Review any Security Defaults transition and replacement protection.
- [ ] Separately enable and test actual allow/block/challenge outcomes.

## Device-dependent

- [ ] Intune licence, enrollment, assigned compliance policy, and recent check-in evidenced.
- [ ] E07 compliant-device T02/T08 results captured.
- [ ] E07 noncompliant and unknown-device T03/T04/T09 results captured.
- [ ] CA003 status changed from designed-unverified only after the evidence above passes review.

## Azure workload-dependent

- [ ] Subscription/resource group, cost/budget, host, and network path approved.
- [ ] Azure deployment What If reviewed and saved.
- [ ] Identity attached to selected host; host selection and direct plus inherited role assignments exported.
- [ ] E09 probe proves `allowed` success and `denied` authorization failure with the same identity.
- [ ] Cleanup completed and evidenced after demonstration.

## Interview-ready handoff

- [x] Curated observed evidence pack ties completed claims to source artifacts; correlation gaps remain explicit.
- [x] Known limitations and unrun cases remain visible.
- [ ] Demonstration rehearsed: threat â†’ policy choice â†’ preview â†’ evaluation â†’ troubleshooting â†’ recovery.
- [ ] `REVIEW.md` questions resolved or explicitly accepted.
