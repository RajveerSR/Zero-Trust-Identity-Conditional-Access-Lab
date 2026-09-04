from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import call, patch

import scripts.disable_policy as disable_policy
import scripts.enable_policy as enable_policy
import scripts.build_policy_identity_record as build_policy_identity_record
from src.ca_policy import REPORT_ONLY_STATE
from src.graph_cli import GRAPH_ROOT, GraphCliError


ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
POLICY_ID = "c001c001-c001-4001-8001-c001c001c001"
POLICY_NAME = "ZT-LAB-CA001-Require-MFA-Pilot"


def write_record(directory: Path, **overrides) -> Path:
    document = {
        "schemaVersion": 1,
        "owner": "Zero Trust Identity & Conditional Access Lab",
        "tenantId": TENANT_ID,
        "policies": {"CA001": {"id": POLICY_ID, "displayName": POLICY_NAME}},
    }
    document.update(overrides)
    path = directory / "policy-identities.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def enable_args(record: Path, confirm: str | None = None) -> list[str]:
    return [
        "--policy-record",
        str(record),
        "--policy-key",
        "CA001",
        "--policy-dir",
        str(ROOT / "policies"),
        "--change-reference",
        "CHG-OFFLINE-TEST",
        "--confirm",
        confirm or f"ENABLE:CA001:{POLICY_ID}",
    ]


def disable_args(record: Path, confirm: str | None = None) -> list[str]:
    return [
        "--policy-record",
        str(record),
        "--policy-key",
        "CA001",
        "--policy-dir",
        str(ROOT / "policies"),
        "--incident-reference",
        "INC-OFFLINE-TEST",
        "--confirm",
        confirm or f"DISABLE:CA001:{POLICY_ID}",
    ]


class PolicyStateScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.record = write_record(Path(self.temp.name))
        self.url = f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{POLICY_ID}"

    @patch("scripts.enable_policy.graph_request")
    @patch("scripts.enable_policy.assert_graph_tenant")
    def test_enable_wrong_confirmation_performs_no_graph_operation(self, tenant, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = enable_policy.main(enable_args(self.record, "ENABLE:WRONG"))
        self.assertEqual(1, result)
        tenant.assert_not_called()
        request.assert_not_called()

    @patch("scripts.enable_policy.graph_request")
    @patch("scripts.enable_policy.assert_graph_tenant", side_effect=GraphCliError("wrong tenant"))
    def test_enable_wrong_tenant_performs_no_graph_operation(self, tenant, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = enable_policy.main(enable_args(self.record))
        self.assertEqual(1, result)
        tenant.assert_called_once_with(TENANT_ID)
        request.assert_not_called()

    @patch("scripts.enable_policy.graph_request")
    @patch("scripts.enable_policy.assert_graph_tenant")
    def test_enable_rejects_unrelated_fetched_policy(self, _tenant, request) -> None:
        request.return_value = {"id": POLICY_ID, "displayName": "Unrelated-Policy", "state": REPORT_ONLY_STATE}
        with redirect_stderr(io.StringIO()):
            result = enable_policy.main(enable_args(self.record))
        self.assertEqual(1, result)
        request.assert_called_once_with("GET", self.url)

    @patch("scripts.enable_policy.graph_request", return_value=None)
    @patch("scripts.enable_policy.assert_graph_tenant")
    def test_enable_rejects_malformed_graph_object(self, _tenant, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = enable_policy.main(enable_args(self.record))
        self.assertEqual(1, result)
        request.assert_called_once_with("GET", self.url)

    @patch("scripts.enable_policy.graph_request")
    @patch("scripts.enable_policy.assert_graph_tenant")
    def test_enable_patches_only_exact_owned_policy(self, tenant, request) -> None:
        request.side_effect = [
            {"id": POLICY_ID, "displayName": POLICY_NAME, "state": REPORT_ONLY_STATE},
            None,
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            result = enable_policy.main(enable_args(self.record))
        self.assertEqual(0, result)
        tenant.assert_called_once_with(TENANT_ID)
        self.assertEqual([call("GET", self.url), call("PATCH", self.url, {"state": "enabled"})], request.call_args_list)
        self.assertIn(f"TARGET tenant={TENANT_ID}", output.getvalue())
        self.assertIn(POLICY_NAME, output.getvalue())

    @patch("scripts.disable_policy.graph_request")
    @patch("scripts.disable_policy.assert_graph_tenant")
    def test_disable_rejects_mismatched_policy_id(self, _tenant, request) -> None:
        request.return_value = {
            "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "displayName": POLICY_NAME,
            "state": "enabled",
        }
        with redirect_stderr(io.StringIO()):
            result = disable_policy.main(disable_args(self.record))
        self.assertEqual(1, result)
        request.assert_called_once_with("GET", self.url)

    @patch("scripts.disable_policy.graph_request")
    @patch("scripts.disable_policy.assert_graph_tenant")
    def test_disable_patches_only_exact_owned_policy(self, tenant, request) -> None:
        request.side_effect = [
            {"id": POLICY_ID, "displayName": POLICY_NAME, "state": "enabled"},
            None,
        ]
        with redirect_stdout(io.StringIO()):
            result = disable_policy.main(disable_args(self.record))
        self.assertEqual(0, result)
        tenant.assert_called_once_with(TENANT_ID)
        self.assertEqual([call("GET", self.url), call("PATCH", self.url, {"state": "disabled"})], request.call_args_list)

    @patch("scripts.disable_policy.graph_request")
    @patch("scripts.disable_policy.assert_graph_tenant")
    def test_disable_already_disabled_is_noop(self, _tenant, request) -> None:
        request.return_value = {"id": POLICY_ID, "displayName": POLICY_NAME, "state": "disabled"}
        with redirect_stdout(io.StringIO()):
            result = disable_policy.main(disable_args(self.record))
        self.assertEqual(0, result)
        request.assert_called_once_with("GET", self.url)

    @patch("scripts.enable_policy.graph_request")
    @patch("scripts.enable_policy.assert_graph_tenant")
    def test_example_record_cannot_authorize_change(self, tenant, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = enable_policy.main(enable_args(ROOT / "config" / "policy-identities.example.json"))
        self.assertEqual(1, result)
        tenant.assert_not_called()
        request.assert_not_called()

    def test_builder_creates_record_from_exact_postdeployment_export(self) -> None:
        temp_path = Path(self.temp.name)
        export_path = temp_path / "postdeployment.json"
        output_path = temp_path / "built-policy-identities.json"
        exported = {
            "evidenceMetadata": {
                "type": "tenant-configuration-export",
                "tenantId": TENANT_ID,
                "capturedAtUtc": "2026-09-04T12:00:00Z",
            },
            "value": [
                {"id": POLICY_ID, "displayName": POLICY_NAME},
                {
                    "id": "c002c002-c002-4002-8002-c002c002c002",
                    "displayName": "ZT-LAB-CA002-Require-Phishing-Resistant-MFA-Admins",
                },
                {
                    "id": "c003c003-c003-4003-8003-c003c003c003",
                    "displayName": "ZT-LAB-CA003-Require-Compliant-Device-Sensitive-App",
                },
            ],
        }
        export_path.write_text(json.dumps(exported), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            result = build_policy_identity_record.main(
                [
                    "--policy-export",
                    str(export_path),
                    "--policy-dir",
                    str(ROOT / "policies"),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(0, result)
        record = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(TENANT_ID, record["tenantId"])
        self.assertEqual(POLICY_ID, record["policies"]["CA001"]["id"])
        self.assertFalse(record["example"])

    def test_builder_rejects_ambiguous_policy_name(self) -> None:
        temp_path = Path(self.temp.name)
        export_path = temp_path / "duplicate.json"
        output_path = temp_path / "should-not-exist.json"
        duplicate = {
            "evidenceMetadata": {"type": "tenant-configuration-export", "tenantId": TENANT_ID},
            "value": [
                {"id": POLICY_ID, "displayName": POLICY_NAME},
                {
                    "id": "c009c009-c009-4009-8009-c009c009c009",
                    "displayName": POLICY_NAME,
                },
            ],
        }
        export_path.write_text(json.dumps(duplicate), encoding="utf-8")
        error = io.StringIO()
        with redirect_stderr(error):
            result = build_policy_identity_record.main(
                [
                    "--policy-export",
                    str(export_path),
                    "--policy-dir",
                    str(ROOT / "policies"),
                    "--output",
                    str(output_path),
                ]
            )
        self.assertEqual(1, result)
        self.assertIn("expected exactly one", error.getvalue())
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
