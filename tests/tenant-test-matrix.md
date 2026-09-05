# Tenant test matrix

Use controlled test accounts and record UTC time, policy version/commit, Graph policy IDs, client, target resource ID, device ID/state, expected result, actual result, sign-in ID, and evidence path. “Expected enforced result” is not an observed claim.

## Evidence levels

| Level | What it proves | What it does not prove |
|---|---|---|
| Local validation | JSON shape, safety invariants, references, deterministic drift | Tenant objects exist or Microsoft Entra accepts/evaluates the definition |
| Change preview | Intended create/update/no-change relative to an export | Live state has not changed since export; no mutation occurs |
| What If | Given inputs make policies applicable/non-applicable and shows controls | Live authentication, real compliance state, service dependencies, or enforcement |
| Report-only sign-in | Real sign-in was evaluated and predicts per-policy result | The report-only policy challenged or blocked the user |
| Enforced sign-in | Enabled policy and actual sign-in outcome/control | Every future path behaves identically |

## Cases

| Case | Persona | Resource | Device/auth state | What If expectation | Report-only expectation | Enforced expectation | Required evidence |
|---|---|---|---|---|---|---|---|
| T01 | Ordinary user | Nonsensitive cloud app | No MFA claim; usable method registered | CA001 applies; CA002/3 do not | CA001 `reportOnlyUserActionRequired`; no prompt from policy | MFA prompt completed, access allowed | What If + sign-in CA detail |
| T02 | Ordinary user | Sensitive app | Known compliant Windows device + MFA | CA001 and CA003 apply | Both predicted success | Allowed after MFA | Device ID/compliance timestamp + sign-in |
| T03 | Ordinary user | Sensitive app | Known noncompliant Windows device + MFA | CA001 and CA003 apply | CA003 report-only failure | Denied by CA003 | Intune state + matching sign-in failure |
| T04 | Ordinary user | Sensitive app | Unregistered/unknown Windows device + MFA | CA001 and CA003 apply | CA003 report-only failure | Denied by CA003 | Client/device detail + sign-in failure |
| T05 | Ordinary user | Sensitive app | Member of device exception + MFA | CA001 applies; CA003 excluded | CA001 only | Allowed after MFA | Approved/expiring exception record + sign-in |
| T06 | Lab admin | Nonsensitive cloud app | Phishing-resistant method | CA001 + CA002 | Both predicted success | Allowed | Auth method detail + sign-in |
| T07 | Lab admin | Nonsensitive cloud app | Push/TOTP only; strong method registered | CA001 + CA002 | CA002 `reportOnlyInterrupted` (or actual returned result explained from the existing claim); capture the service result rather than assuming one | Strong method required; weak-only attempt cannot complete | Sign-in auth/CA detail |
| T08 | Lab admin | Sensitive app | Strong method + compliant Windows device | CA001 + CA002 + CA003 | All predicted success | Allowed | What If + device + auth + sign-in |
| T09 | Lab admin | Sensitive app | Strong method + noncompliant Windows device | CA001 + CA002 + CA003 | CA003 predicted failure | Denied | Matching Intune and sign-in records |
| T10 | Emergency access 1 | Any target | Approved quarterly drill | All three excluded | Lab policies not applied | Lab policies do not restrict sign-in | Alert + sign-in + drill record; never secret material |
| T11 | Emergency access 2 | Any target | Approved quarterly drill | Same as T10 | Same as T10 | Same as T10 | Independent credential/path evidence |
| T12 | Out-of-scope user | Any | Any | No lab policy applies | No lab policy result | No effect from lab policies | What If or sign-in showing nonapplication |
| T13 | Managed identity | `allowed` Blob container | Azure-host token | N/A | N/A | Blob list succeeds via Azure RBAC | Workload probe JSON + role assignment |
| T14 | Managed identity | `denied` Blob container | Same token/host/time window | N/A | N/A | Authorization denial | Workload probe JSON; confirm it is not network failure |

If device prerequisites are unavailable, mark T02–T05, T08–T09 **not run — designed but unverified**. Do not convert an assumed device state into observed evidence.
