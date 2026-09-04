# Rollout and recovery

- Use [rollout-runbook.md](rollout-runbook.md) for validation, report-only creation, What If, observation, and the separately approved enable action.
- Use [recovery-runbook.md](recovery-runbook.md) for lockout recovery and diagnosis.

The non-negotiable invariant is: **local validation → current-state export → preview → report-only → What If → observed report-only sign-ins → one-policy enable → enforced sign-ins**. Device enforcement stops before enablement unless real Intune evidence exists.
