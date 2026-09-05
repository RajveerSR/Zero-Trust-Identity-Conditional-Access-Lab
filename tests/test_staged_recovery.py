from __future__ import annotations
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from scripts import build_policy_identity_record as builder, validate_policies as validator
from src.policy_identity import load_policy_identity, PolicyIdentityError

ROOT = Path(__file__).resolve().parents[1]
TENANT = "d0000000-1111-4111-8111-111111111111"
IDS = {"CA001": "c001c001-c001-4001-8001-c001c001c001", "CA002": "c002c002-c002-4002-8002-c002c002c002"}

class StagedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.export = self.root / "post.json"
        self.record = self.root / "record.json"
        self.policies = []
        for key, suffix in [("CA001", "Require-MFA-Pilot"), ("CA002", "Require-Phishing-Resistant-MFA-Admins")]:
            self.policies.append({"id": IDS[key], "displayName": f"ZT-LAB-{key}-{suffix}"})
        self.write_export()
        self.args = ["--policy-export", str(self.export), "--output", str(self.record)]

    def write_export(self):
        self.export.write_text(json.dumps({"evidenceMetadata": {"type": "tenant-configuration-export", "tenantId": TENANT}, "value": self.policies}), encoding="utf-8")

    def run_builder(self, extra):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return builder.main(self.args + extra)

    def test_two_policy_record_supports_recovery_without_authorizing_third(self):
        self.assertEqual(0, self.run_builder(["--policy-id", "CA001", "--policy-id", "CA002"]))
        for key in IDS:
            identity = load_policy_identity(self.record, key, ROOT / "policies")
            self.assertEqual(IDS[key], identity.policy_id)
            self.assertEqual(TENANT, identity.tenant_id)
        with self.assertRaises(PolicyIdentityError):
            load_policy_identity(self.record, "CA003", ROOT / "policies")

    def test_full_rollout_still_requires_all_three(self):
        self.assertEqual(1, self.run_builder([]))
        self.assertFalse(self.record.exists())

    def test_missing_or_ambiguous_selected_policy_cannot_produce_record(self):
        for mode in ("missing", "duplicate"):
            with self.subTest(mode=mode):
                self.policies = [] if mode == "missing" else [self.policies[0], self.policies[0]]
                self.write_export()
                self.assertEqual(1, self.run_builder(["--policy-id", "CA001"]))
                self.assertFalse(self.record.exists())
                if mode == "missing":
                    self.policies = [{"id": IDS["CA001"], "displayName": "ZT-LAB-CA001-Require-MFA-Pilot"}]

    def test_duplicate_selection_is_refused(self):
        self.assertEqual(1, self.run_builder(["--policy-id", "CA001", "--policy-id", "CA001"]))
        self.assertFalse(self.record.exists())

    def test_unresolved_device_app_is_a_failed_validation_not_a_success_banner(self):
        config = self.root / "tenant.json"
        config.write_text('{"values": {}}', encoding="utf-8")
        args = ["validate_policies.py", "--config", str(config), "--policy-id", "CA003"]
        with patch("sys.argv", args), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(1, validator.main())
        self.assertIn("SENSITIVE_APP_ID", output.getvalue())
        self.assertNotIn("OK:", output.getvalue())
