# Evidence index

`examples/` contains synthetic illustrations; `local/` records executed offline checks; `observed/` contains curated real observations. Raw tenant exports remain ignored under `tenant/` or in the private workspace.

| ID | Capability | Current evidence / limitation |
|---|---|---|
| E00 | Local regression | 67 Python tests passed on 5 September; earlier seven workload classification cases remain documented separately |
| E01/E02 | Validation and preview | Three definitions validate; live-config preview: CA001 UNCHANGED, CA002 UNCHANGED, CA003 CREATE (not applied) |
| E03 | Tenant configuration | [Redacted readback](observed/2026-09-05/configuration.redacted.json): CA001/CA002 report-only |
| E04 | What If | [Three live simulations](observed/2026-09-05/what-if.redacted.json); assumed Windows/browser inputs |
| E05 | Report-only observation | [Portal screenshots](observed/2026-09-05/README.md); exact event correlation/API discrepancy unresolved |
| E06 | Enforced access | Not run |
| E07 | Device compliance | Not run; no Intune entitlement or test device observed |
| E08 | Recovery drill | Not run; emergency group empty |
| E09 | Workload identity | Not run; no Azure resources deployed |
| E10 | Shared identities | Existing governance groups used; private exact identifiers reconciled; no competing users created |

Configuration is not enforcement. What If inputs are hypothetical, and report-only success is an evaluation result. Preserve original observations, document uncertainty and never treat a network/RBAC/application failure as proof of a Conditional Access block. Source hashes detect later changes; they are not authenticated provenance.
