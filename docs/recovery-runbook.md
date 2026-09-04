# Recovery and troubleshooting runbook

## Trigger conditions

Disable the newly enabled policy if expected users cannot access required resources, administrator recovery methods fail, compliant devices are consistently reported unknown, the wrong group/app is in scope, or the emergency-access path is the only remaining administrative route.

## Immediate recovery

1. Record UTC start, symptom, affected personas/resources, last known good state, and incident/change reference.
2. Use a designated secure workstation and one coordinated emergency-access account. Confirm the account is excluded from the suspect policy; do not change shared identity provisioning here.
3. In Entra admin center, locate the policy by exact Graph ID and set it **Off**, or run:

```powershell
python scripts/disable_policy.py `
  --policy-id <graph-policy-uuid> `
  --expected-tenant-id <tenant-id> `
  --incident-reference INC-EXAMPLE `
  --confirm DISABLE:<graph-policy-uuid>
```

4. Verify the policy reads `disabled`, then retry using a fresh/private session so stale tokens do not obscure the outcome.
5. If more than one policy changed, disable only the newest/suspect policy first. Applicable policies accumulate, so another tenant policy may still deny access.
6. Preserve pre/post policy exports, audit logs, sign-in IDs, and exact failure codes. Alert monitoring staff that emergency access was used and complete a post-incident review.

If scripts are unavailable, use the Entra admin center from the emergency session. Do not make the emergency account dependent on the broken device, federation, PIM activation, or authentication path.

## Diagnosis sequence

1. **Identity:** confirm user object, direct/transitive group membership, exclusions, guest type, and role activation timing.
2. **Resource:** use sign-in log `resourceDisplayName/resourceId`, not the friendly application name alone. Check service dependencies.
3. **Policies:** inspect every applied enabled/report-only policy and its result. `conditionalAccessStatus: success` can mean policies were evaluated, not that every displayed policy applied.
4. **Authentication:** examine authentication requirement/details and claim age. For CA002, confirm the actual method is allowed by the referenced strength.
5. **Device:** confirm Entra device ID, registration/join type, Intune enrollment, assigned compliance policy, last check-in, compliance reason, supported platform, and client/browser certificate/device claim behaviour.
6. **Client:** distinguish browser, modern desktop/mobile, noninteractive refresh, and legacy clients. Reproduce with controlled client state.
7. **Timing:** allow for group/RBAC propagation and sign-in-log ingestion; record actual times rather than repeatedly changing policy.

## Restore and reintroduce

Compare the disabled tenant object with `evidence/tenant/prechange-policies.json` and the reviewed desired definition. Correct the source JSON or identity manifest, run local validation and preview again, redeploy only to report-only, and repeat What If/report-only tests. Do not jump directly from a repaired file to enabled state.

## Emergency-access hygiene after use

Confirm the use was authorized, review actions taken, inspect sign-in/audit logs, rotate or re-secure credentials if exposure is possible, test the second account, close alerts, and document lessons. Microsoft recommends two or more cloud-only accounts, independent phishing-resistant credentials, monitoring, and validation at least every 90 days.
