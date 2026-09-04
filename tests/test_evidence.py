from __future__ import annotations

import unittest

from scripts.collect_signin_evidence import _minimal_event


class EvidenceTests(unittest.TestCase):
    def test_collector_minimises_identity_and_filters_policy_prefix(self) -> None:
        event = {
            "id": "sign-in-1",
            "userId": "user-1",
            "userPrincipalName": "should-not-appear@example.test",
            "userDisplayName": "Should Not Appear",
            "ipAddress": "192.0.2.1",
            "location": {"city": "Example"},
            "authenticationDetails": [
                {
                    "authenticationMethod": "FIDO2 security key",
                    "succeeded": True,
                    "authenticationStepResultDetail": "success",
                }
            ],
            "appliedConditionalAccessPolicies": [
                {"id": "ca-1", "displayName": "ZT-LAB-CA001-Test", "result": "reportOnlySuccess"},
                {"id": "other", "displayName": "Existing-Policy", "result": "success"},
            ],
        }
        reduced = _minimal_event(event, {"user-1": "ordinary-user"}, "ZT-LAB-")
        rendered = str(reduced)
        self.assertEqual("ordinary-user", reduced["persona"])
        self.assertEqual(1, len(reduced["labPolicies"]))
        self.assertEqual("FIDO2 security key", reduced["authenticationDetails"][0]["authenticationMethod"])
        self.assertNotIn("should-not-appear", rendered)
        self.assertNotIn("192.0.2.1", rendered)
        self.assertNotIn("Existing-Policy", rendered)


if __name__ == "__main__":
    unittest.main()
