# Report-only rollout runbook

This runbook prepares and evaluates changes. It does not authorize tenant modification. Use a recorded change window and keep an emergency-access operator outside the normal admin session. Export and preview are read-only; creating report-only policies still changes tenant configuration even though those policies do not enforce controls.

## 1. Local validation

```powershell
python scripts/validate_policies.py --config config/lab-identities.json --config config/tenant.json
python -m unittest discover -s tests -v
```

Stop on any error. Review metadata and Graph body together; deployment emits only `graph`.

## 2. Coordinate and snapshot

1. Complete [prerequisites.md](prerequisites.md), including shared-tenant coordination.
2. Sign in to the correct tenant with the least-privileged temporary role/scopes needed for the operation.
3. Confirm the active tenant and operator independently.
4. Export current policy state:

```powershell
az login --tenant <tenant-id>
python scripts/export_current_policies.py `
  --expected-tenant-id <tenant-id> `
  --output evidence/tenant/prechange-policies.json
```

5. Preview desired against current:

```powershell
python scripts/preview_changes.py `
  --config config/lab-identities.json `
  --config config/tenant.json `
  --current evidence/tenant/prechange-policies.json
```

Inspect every `CREATE`/`UPDATE`, all existing policies with overlapping scope, and any display-name collision. An existing enabled policy with the same name causes the deploy script to stop. A same-name policy with non-empty settings absent from source also causes deployment to stop, because a Graph PATCH that omits those settings might retain unintended behaviour.

## 3. Create report-only policies

The command below is mutating and intentionally requires an explicit flag. It cannot deploy an `enabled` repository definition and refuses example manifests.

Microsoft Graph does not make a multi-policy run atomic. If a later request fails after an earlier create/update succeeds, the script reports completed and last-attempted work and stops. Do not assume rollback: take a fresh export and preview before any recovery or retry.

```powershell
python scripts/deploy_report_only.py `
  --config config/lab-identities.json `
  --config config/tenant.json `
  --apply-report-only
```

Immediately export again and verify all three objects are in `enabledForReportingButNotEnforced`. Then create the ignored, tenant-bound identity record used by the enable and recovery commands:

```powershell
python scripts/export_current_policies.py `
  --expected-tenant-id <tenant-id> `
  --output evidence/tenant/postdeployment-policies.json

python scripts/build_policy_identity_record.py `
  --policy-export evidence/tenant/postdeployment-policies.json `
  --output config/policy-identities.json
```

The builder requires one exact exported match for each repository policy. Keep Graph IDs in this scoped record and the change/evidence record, not in deployable policy templates.

## 4. What If evaluation

In Entra admin center, go to **Entra ID > Conditional Access > Policies > What If**. Test each row in [../tests/tenant-test-matrix.md](../tests/tenant-test-matrix.md), supplying identity, target resource, device platform, and client app. Save a screenshot or structured note containing UTC time, inputs, applicable/non-applicable policies, and grant controls.

What If predicts policy applicability; it does not perform authentication, validate a live device-compliance claim, model every service dependency, or prove enforcement.

## 5. Report-only observation

Generate controlled pilot sign-ins for each available persona/device state. Wait for log ingestion, then collect a narrow UTC window:

```powershell
python scripts/collect_signin_evidence.py `
  --since 2026-09-04T09:00:00Z `
  --until 2026-09-04T10:00:00Z `
  --identity-config config/lab-identities.json `
  --tenant-config config/tenant.json `
  --output evidence/tenant/report-only-signins.json
```

Inspect per-policy `reportOnly...` results, device detail, resource, status, and existing-policy interactions. A report-only failure means the request would have failed that policy's grant requirement had it been enabled; the actual request was not blocked by that report-only policy.

## 6. Enforcement gates

Enable only one policy at a time and only after all its matrix cases pass review:

- correct includes and exclusions in What If;
- no unexpected report-only impact across a representative observation window;
- successful emergency-access drill and monitoring alert;
- required authentication methods ready for every in-scope admin;
- help/recovery owner available;
- for CA003, both compliant and noncompliant/unknown states evidenced. Otherwise CA003 remains report-only and **designed but unverified**.

## 7. Separate enable action

Record approval and use the tenant-bound identity record. The command verifies tenant ID, repository policy key, Graph ID, and exact display name before PATCH. Start with CA001's pilot cohort; observe; then CA002; CA003 last.

```powershell
python scripts/enable_policy.py `
  --policy-record config/policy-identities.json `
  --policy-key CA001 `
  --change-reference CHG-EXAMPLE `
  --confirm ENABLE:CA001:<graph-policy-uuid>
```

Immediately run the enforced cases, capture sign-in outcomes, and monitor help/lockout signals. Never label a report-only record as enforced evidence.

## 8. Completion

Export post-change configuration, hash or otherwise integrity-protect the evidence package, update [../evidence/index.md](../evidence/index.md), and reconcile the shared change record with the Enterprise Identity Governance Lab.
