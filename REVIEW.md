# Independent review handoff

## Current state - 5 September 2026

- CA001 and CA002 were created through the repository deployer in report-only mode. Exact IDs, names, scopes, grants and state were checked against source; preview reports both UNCHANGED.
- Two supplied Entra screenshots show report-only success and a Previously satisfied authentication step. The original authentication method is not independently captured.
- Live Graph What If succeeds for administrator, ordinary-user and disabled-leaver applicability checks. The leaver result is not a sign-in or authorization success.
- CA003 validates with a verified Azure Resource Manager target in the private configuration, but is not deployed. No Intune SKU/device or Azure workload host/resources were observed.
- Recovery accounts remain deferred; the exclusion group is empty. No policy was enabled for enforcement and no Security Defaults change was issued.
- The existing CLI session has broad delegated privileges. This is not evidence of a least-privilege service identity.

## Engineering verification

67 Python tests pass without network calls, including five new What If guards. The new tool calls only the documented simulation endpoint, validates the tenant, rejects malformed/incomplete results and refuses to overwrite existing evidence. Earlier transport, scope, drift, partial-deployment and recovery-binding tests remain passing.

Earlier milestones: `017e546` scaffold; `84a60db` CLI transport; `85585a6` exact policy ownership; `198eb9a` drift/workload hardening; `acb93d4` staged policy records; `e0190d7` live Graph context normalization; `092b741` report-only enum preference. History is preserved; no remote push was performed.

## Evidence and remaining review

See [observed evidence](evidence/observed/2026-09-05/README.md) and [completion checklist](evidence/completion-checklist.md). Raw exports remain private; supplied screenshots are copied unaltered.

1. Check that every claim distinguishes configuration, simulation, report-only evaluation and enforcement.
2. Confirm the three What If outcomes and the disabled-account limitation.
3. Investigate the unresolved portal/API sign-in-detail discrepancy using a delegated SDK session with policy and audit read scopes; do not substitute invented policy results.
4. Before enforcement, inspect current Security Defaults, recovery coverage, current policy interactions and real allow/block tests.
5. Before CA003, complete Intune enrollment/compliance and both positive and negative device cases. Before workload deployment, review actual host, costs, network and inherited RBAC.

The standalone What If client follows [Microsoft Graph evaluate](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0). Its POST is a simulation action and does not create or enable policies.
