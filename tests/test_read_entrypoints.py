from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import scripts.collect_signin_evidence as collect_signin_evidence
import scripts.export_current_policies as export_current_policies
import scripts.preview_changes as preview_changes
from src.graph_cli import GraphCliError


ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class ReadEntryPointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @patch("scripts.export_current_policies.graph_get_all", return_value=[{"id": "policy-1"}])
    @patch("scripts.export_current_policies.assert_graph_tenant", return_value=TENANT_ID)
    def test_export_writes_tenant_bound_configuration_snapshot(self, tenant, get_all) -> None:
        output = self.root / "policies.json"
        with redirect_stdout(io.StringIO()):
            result = export_current_policies.main(
                ["--expected-tenant-id", TENANT_ID, "--output", str(output)]
            )
        self.assertEqual(0, result)
        tenant.assert_called_once_with(TENANT_ID)
        get_all.assert_called_once()
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(TENANT_ID, document["evidenceMetadata"]["tenantId"])
        self.assertEqual([{"id": "policy-1"}], document["value"])

    @patch("scripts.export_current_policies.graph_get_all")
    @patch("scripts.export_current_policies.assert_graph_tenant", side_effect=GraphCliError("wrong tenant"))
    def test_export_tenant_failure_is_unsuccessful_and_writes_nothing(self, _tenant, get_all) -> None:
        output = self.root / "policies.json"
        with redirect_stderr(io.StringIO()):
            result = export_current_policies.main(
                ["--expected-tenant-id", TENANT_ID, "--output", str(output)]
            )
        self.assertEqual(1, result)
        get_all.assert_not_called()
        self.assertFalse(output.exists())

    @patch("scripts.collect_signin_evidence.graph_get_all")
    @patch("scripts.collect_signin_evidence.assert_graph_tenant", return_value=TENANT_ID)
    def test_evidence_graph_failure_is_unsuccessful_and_writes_nothing(self, _tenant, get_all) -> None:
        identity = self.root / "identities.json"
        tenant = self.root / "tenant.json"
        output = self.root / "signins.json"
        identity.write_text(
            json.dumps({"values": {"LAB_STANDARD_USER_ID": "06666666-6666-4666-8666-666666666666"}}),
            encoding="utf-8",
        )
        tenant.write_text(json.dumps({"values": {"TENANT_ID": TENANT_ID}}), encoding="utf-8")
        get_all.side_effect = GraphCliError("simulated sign-in query failure")
        with redirect_stderr(io.StringIO()):
            result = collect_signin_evidence.main(
                [
                    "--since",
                    "2026-09-04T09:00:00Z",
                    "--identity-config",
                    str(identity),
                    "--tenant-config",
                    str(tenant),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(1, result)
        self.assertFalse(output.exists())

    def test_preview_rejects_ambiguous_duplicate_names_cleanly(self) -> None:
        current = self.root / "duplicate.json"
        current.write_text(
            json.dumps(
                {
                    "value": [
                        {"id": "one", "displayName": "ZT-LAB-CA001-Require-MFA-Pilot"},
                        {"id": "two", "displayName": "ZT-LAB-CA001-Require-MFA-Pilot"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        error = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(error):
            result = preview_changes.main(
                [
                    "--use-example-config",
                    "--policy-dir",
                    str(ROOT / "policies"),
                    "--current",
                    str(current),
                ]
            )
        self.assertEqual(1, result)
        self.assertIn("Ambiguous current state", error.getvalue())


if __name__ == "__main__":
    unittest.main()
