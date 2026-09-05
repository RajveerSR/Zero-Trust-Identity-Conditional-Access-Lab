import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import evaluate_what_if as subject
from src.graph_cli import GraphCliError

TENANT = "d0000000-1111-4111-8111-111111111111"
REQUEST = {
    "signInIdentity": {"@odata.type": "#microsoft.graph.userSignIn", "userId": "e0000000-1111-4111-8111-111111111111"},
    "signInContext": {"@odata.type": "#microsoft.graph.applicationContext", "includeApplications": ["f0000000-1111-4111-8111-111111111111"]},
    "signInConditions": {"clientAppType": "browser", "devicePlatform": "windows"},
    "appliedPoliciesOnly": False,
}


class WhatIfTests(unittest.TestCase):
    def invoke(self, document, tenant_error=None, response=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "request.json", root / "result.json"
            source.write_text(json.dumps(document))
            with patch.object(subject, "assert_graph_tenant", return_value=TENANT, side_effect=tenant_error), patch.object(subject, "graph_request", return_value=response) as graph:
                code = subject.main(["--input", str(source), "--output", str(output), "--expected-tenant-id", TENANT])
                return code, json.loads(output.read_text()) if output.exists() else None, graph.call_args_list

    def test_simulation_calls_only_evaluate_and_labels_assumptions(self):
        code, saved, calls = self.invoke(REQUEST, response={"value": [{"policyApplies": True}]})
        self.assertEqual(0, code)
        self.assertEqual(1, len(calls))
        self.assertEqual(("POST", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate", REQUEST), calls[0].args)
        self.assertIn("assumptions", saved["evidenceMetadata"]["interpretation"])

    def test_tenant_mismatch_never_calls_simulation(self):
        code, saved, calls = self.invoke(REQUEST, tenant_error=GraphCliError("Tenant mismatch"))
        self.assertEqual((1, None, []), (code, saved, calls))

    def test_all_applications_wildcard_rejected_before_graph(self):
        request = json.loads(json.dumps(REQUEST))
        request["signInContext"]["includeApplications"] = ["All"]
        code, saved, calls = self.invoke(request)
        self.assertEqual((1, None, []), (code, saved, calls))

    def test_malformed_and_paginated_responses_never_become_evidence(self):
        for response in (None, {}, {"value": None}, {"value": [], "@odata.nextLink": "https://example.com/next"}):
            with self.subTest(response=response):
                code, saved, _ = self.invoke(REQUEST, response=response)
                self.assertEqual((1, None), (code, saved))

    def test_existing_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.json"
            path.write_text("original")
            with patch.object(subject, "graph_request") as graph:
                self.assertEqual(1, subject.main(["--input", str(path), "--output", str(path), "--expected-tenant-id", TENANT]))
                graph.assert_not_called()
            self.assertEqual("original", path.read_text())
