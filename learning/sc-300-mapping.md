# SC-300 learning map

| Lab capability | SC-300 skill area | Explain without notes |
|---|---|---|
| Shared identity manifest and persona groups | Implement and manage user identities; manage groups | Why object IDs are stable deployment inputs and why ownership stays in the governance lab |
| CA001 baseline MFA | Plan, implement, and manage access with Conditional Access | Assignment, resource, client, grant control, claims, and user impact |
| CA002 authentication strength | Plan and implement authentication methods | Difference between “MFA” and phishing-resistant method combinations; prerequisites and recovery |
| CA003 compliant device | Conditional Access and identity protection | Device registration vs enrollment vs compliance; signal presentation and troubleshooting |
| What If/report-only/enforced taxonomy | Monitor and maintain identity | What each test layer proves and how to read applied-policy results |
| Emergency access | Manage identity governance and resilience | Why exclusion is necessary, what compensating controls reduce bypass risk, and how to drill |
| Graph export/deployment | Monitor and maintain identity | Least-privileged scopes/roles, idempotent comparison, current-state capture, rollback |
| Managed identity + scoped Azure RBAC | Plan and implement workload identities | Token acquisition without stored secrets; control plane vs data plane; role, scope, principal |

## Original practice scenarios

1. An admin can satisfy CA001 with push MFA but fails CA002. Trace which policy failed, explain why `OR` inside CA001 does not weaken CA002, and propose a safe recovery that does not exclude the admin.
2. A Windows device is visible in Entra and Intune but CA003 reports failure. Separate registration, enrollment, compliance assignment, check-in, browser/device certificate, resource ID, and stale-session hypotheses.
3. The sensitive app sign-in log shows CA003 “not applied.” Use group membership, resource ID, exclusions, client type, and existing policy interactions to find the first mismatched condition.
4. The workload can read both containers. Inspect role-assignment scope and inherited assignments before changing code; explain why MFA would not address the problem.
5. The denied-container probe fails with DNS timeout. Explain why that is not least-privilege evidence and what observation would be.
6. A report-only event says `reportOnlyFailure`, but the user accessed the app. Explain the apparent contradiction and what must be captured after enablement to claim enforcement.
7. The ordinary-user group is changed by the governance repository during a CA rollout. Describe the coordination record, new blast-radius review, preview limitations, and whether to pause.
