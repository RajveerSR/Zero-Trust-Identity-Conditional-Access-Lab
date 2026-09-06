# Local and live verification - 5 September 2026

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` | 67 tests passed without network calls |
| Three policies validated with private resolved configuration | Passed |
| Preview against verified two-policy export | CA001 UNCHANGED; CA002 UNCHANGED; CA003 CREATE; no apply |
| New `evaluate_what_if.py` live simulation | Three scenarios each returned the two deployed policies; no configuration changes |
| JSON parsing and local Markdown/image links | Passed |
| Private tenant/operator markers and JWT-shaped values in tracked/unignored text | None found by the bounded scan |
| `git diff --check` | Passed after preserving LF line endings |

Five new tests cover the simulation-only endpoint, exact tenant refusal, wildcard application rejection, malformed/paginated response refusal, and protection of existing evidence. Earlier transport, ownership, drift, partial-deployment and evidence-header cases remain passing.

The [observed pack](../observed/2026-09-05/README.md) separates real configuration, hypothetical What If inputs and supplied portal screenshots. No enforced sign-in, compliant-device result, recovery drill or Azure workload result is claimed. The CLI/portal detail discrepancy remains unresolved; a read-only SDK session is prepared for later user participation.
