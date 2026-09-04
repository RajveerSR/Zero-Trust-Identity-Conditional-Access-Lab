# Evidence index

No checked-in file currently proves a tenant deployment or enforced sign-in. `examples/` contains synthetic formatting examples only. Real tenant artifacts belong under ignored `evidence/tenant/` and should be reviewed for personal/sensitive data before sharing.

| Evidence ID | Capability | Required level | Expected path | Current state |
|---|---|---|---|---|
| E01 | Policy source validation | Local | `evidence/examples/local-validation.txt` | Synthetic example; regenerate locally |
| E02 | Change intent | Preview | `evidence/examples/change-preview.txt` | Synthetic fixture-based example; regenerate locally |
| E03 | Tenant policy configuration | Tenant export | `evidence/tenant/prechange-policies.json`, `postchange-policies.json` | Not collected |
| E04 | Scope/control prediction | What If | `evidence/tenant/what-if-<case>.*` | Not collected |
| E05 | Actual evaluation | Report-only sign-ins | `evidence/tenant/report-only-signins.json` | Not collected |
| E06 | Actual control | Enforced sign-ins | `evidence/tenant/enforced-signins.json` | Not collected |
| E07 | Device assurance | Intune + sign-in correlation | `evidence/tenant/device-<case>.*` | Not collected; designed but unverified |
| E08 | Emergency recovery | Drill + alert + sign-in | `evidence/tenant/emergency-drill.*` | Not collected |
| E09 | Workload least privilege | Deployment/RBAC + positive/negative probe | `evidence/tenant/workload-probe.json` | Not collected; designed but unverified |
| E10 | Shared-tenant coordination | Change record | `evidence/tenant/shared-change-record.*` | Not collected |

## Evidence quality rules

- State whether an artifact is source, preview, simulation, report-only observation, or enforced observation.
- Record UTC timestamps, commit SHA, tenant display name/ID (non-secret), policy Graph IDs, test case, and collector/version.
- Correlate sign-in ID, resource, device state, and applicable policy result. A screenshot without inputs/context is weak evidence.
- Minimise UPNs, names, IP addresses, locations, tokens, and device identifiers. Never record credentials or access tokens.
- Capture both allowed and denied cases. A denial caused by networking, bad syntax, or missing app assignment is not proof of the intended control.
- Preserve the unedited source artifact privately; use a redacted copy for interview/public presentation and record what was redacted.
- A report-only failure is a prediction. Only an enabled policy plus the actual sign-in outcome supports an enforcement claim.
