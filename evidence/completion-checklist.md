# Capability-to-evidence completion checklist

## Local and design

- [x] Threats, identities, resources, boundaries, and residual risks documented — `docs/threat-model.md`.
- [x] Three minimal policy definitions include purpose, scope, exclusions, controls, prerequisites, impact, and status — `policies/*.json`.
- [x] Policy interaction and expected outcomes documented — `docs/policy-matrix.md`.
- [x] Local validation and deterministic tests implemented — `scripts/validate_policies.py`, `tests/test_ca_policy.py`.
- [x] Readable create/update/no-change preview implemented — `scripts/preview_changes.py`.
- [x] Report-only deployment guarded from example config and enabled state — `scripts/deploy_report_only.py`.
- [x] Enforcement is a separate single-policy action — `scripts/enable_policy.py`.
- [x] Emergency exclusion, monitoring, drill, and recovery model documented — `docs/recovery-runbook.md`.
- [x] Shared identities consumed via an explicit non-secret manifest — `config/lab-identities.example.json`.
- [x] Managed-identity least-privilege scenario and positive/negative probe prepared — `infra/`, `docs/workload-identity.md`.
- [x] Local evidence is explicitly labelled synthetic — `evidence/examples/`.

## Tenant-dependent Conditional Access

- [ ] E10 shared change record approved; IDs reconciled with Enterprise Identity Governance Lab.
- [ ] E03 prechange Conditional Access export captured and reviewed.
- [ ] Report-only deployment completed with Graph response IDs recorded.
- [ ] E03 postdeployment export proves all definitions remain report-only.
- [ ] E04 What If evidence captured for every available T01–T12 case.
- [ ] E05 report-only sign-ins captured and reconciled to expectations.
- [ ] Emergency-access monitoring alert and both-account drill evidenced (E08).
- [ ] Approval recorded for each separate enable action.
- [ ] E06 actual enforced allow and deny/challenge outcomes captured per enabled policy.

## Device-dependent

- [ ] Intune licence, enrollment, assigned compliance policy, and recent check-in evidenced.
- [ ] E07 compliant-device T02/T08 results captured.
- [ ] E07 noncompliant and unknown-device T03/T04/T09 results captured.
- [ ] CA003 status changed from designed-unverified only after the evidence above passes review.

## Azure workload-dependent

- [ ] Subscription/resource group, cost/budget, host, and network path approved.
- [ ] Azure deployment What If reviewed and saved.
- [ ] Identity attached to selected host; container-scoped role assignment exported.
- [ ] E09 probe proves `allowed` success and `denied` authorization failure with the same identity.
- [ ] Cleanup completed and evidenced after demonstration.

## Interview-ready handoff

- [ ] Redacted evidence pack ties each claim to an evidence ID and test case.
- [ ] Known limitations and unrun cases remain visible.
- [ ] Demonstration rehearsed: threat → policy choice → preview → evaluation → troubleshooting → recovery.
- [ ] `REVIEW.md` questions resolved or explicitly accepted.
