# Conditional Access policy matrix

All definitions are checked in as `enabledForReportingButNotEnforced`. The expected **enforced** outcomes below are hypotheses until the corresponding tenant evidence is captured.

| ID | Purpose | Include scope | Exclusions | Grant control | Prerequisites | Expected user impact |
|---|---|---|---|---|---|---|
| CA001 | Baseline account-takeover resistance | Shared lab-user and lab-admin groups; all resources; all clients | Emergency-access group; MFA exception group | Require MFA | Entra ID P1; registered MFA; tested recovery | In enforcement, prompt when no acceptable MFA claim exists |
| CA002 | Stronger privileged authentication | Shared lab-admin group; all resources; all clients | Emergency-access group | Built-in phishing-resistant MFA strength | Entra ID P1; enabled and registered FIDO2/passkey, WHfB, or qualifying CBA; verified strength ID | In enforcement, weak MFA alone cannot satisfy the policy |
| CA003 | Device assurance for sensitive data | Shared lab-user and lab-admin groups; sensitive resource only; Windows; all clients | Emergency-access group; device exception group | Require compliant device | Entra ID P1, Intune licensing, assigned compliance policy, registered/enrolled/recently evaluated Windows device, supported client | In enforcement, unknown/noncompliant devices fail access to the sensitive app |

## Interaction cases

Conditional Access evaluates every applicable policy. Grant requirements in separate applicable policies accumulate; the `OR` in each JSON body applies only among controls inside that one policy.

| Persona and request | Applicable lab policies | Expected enforced result | Reason |
|---|---|---|---|
| Ordinary user, nonsensitive app, MFA available | CA001 | Allow after MFA | Baseline only |
| Ordinary user, sensitive app, compliant Windows device | CA001 + CA003 | Allow after MFA with compliant signal | Both policies satisfied |
| Ordinary user, sensitive app, noncompliant/unknown Windows device | CA001 + CA003 | Deny after authentication | Device grant is not satisfied |
| Lab admin, nonsensitive app, phishing-resistant method | CA001 + CA002 | Allow | Strong method satisfies CA002 and provides MFA for CA001 |
| Lab admin, nonsensitive app, push/TOTP only | CA001 + CA002 | Deny or require method change | CA001 may pass, CA002 does not |
| Lab admin, sensitive app, strong method, compliant Windows device | CA001 + CA002 + CA003 | Allow | All three independent requirements satisfied |
| Emergency-access account | None of these policies | These policies do not restrict it | Explicit group exclusion; credentials and monitoring are compensating controls |
| Ordinary user in device-exception group, sensitive app | CA001 only | Allow after MFA | CA003 exclusion is narrow; CA001 still applies |
| Managed identity probes Blob containers | None | Allowed container succeeds; sibling denied | Azure RBAC, not human Conditional Access |

Non-Windows platforms are outside CA003 v0.1. The scope is intentional: current Microsoft guidance notes that report-only compliant-device policies can still prompt macOS, iOS, and Android users to select a device certificate. Expand platforms only with explicit client prerequisites and impact testing.

## Exception contract

An exception is a temporary risk decision, not a troubleshooting shortcut. For every exception-group membership, record requester, approver, business reason, affected policy, start/end time, compensating control, and removal evidence in the system that owns group membership. The Enterprise Identity Governance Lab remains the owner of shared group membership; this repository records the coordination reference with the evidence package.
