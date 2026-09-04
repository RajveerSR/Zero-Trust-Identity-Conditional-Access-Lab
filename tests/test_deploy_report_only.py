from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import scripts.deploy_report_only as deploy_report_only
from src.ca_policy import graph_payload, load_config, load_policy_documents, resolve_policy
from src.graph_cli import GRAPH_ROOT, GraphCliError


ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


IDENTITY_VALUES = {
    "LAB_USERS_GROUP_ID": "01111111-1111-4111-8111-111111111111",
    "LAB_ADMINS_GROUP_ID": "02222222-2222-4222-8222-222222222222",
    "EMERGENCY_ACCESS_GROUP_ID": "03333333-3333-4333-8333-333333333333",
    "CA_MFA_EXCEPTION_GROUP_ID": "04444444-4444-4444-8444-444444444444",
    "CA_DEVICE_EXCEPTION_GROUP_ID": "05555555-5555-4555-8555-555555555555",
    "LAB_STANDARD_USER_ID": "06666666-6666-4666-8666-666666666666",
    "LAB_ADMIN_USER_ID": "07777777-7777-4777-8777-777777777777",
    "EMERGENCY_ACCESS_USER_1_ID": "08888888-8888-4888-8888-888888888888",
    "EMERGENCY_ACCESS_USER_2_ID": "09999999-9999-4999-8999-999999999999",
}
TENANT_VALUES = {
    "TENANT_ID": TENANT_ID,
    "SENSITIVE_APP_ID": "0bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "PHISHING_RESISTANT_AUTH_STRENGTH_ID": "00000000-0000-0000-0000-000000000004",
}


class DeployReportOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.identity_config = root / "lab-identities.json"
        self.tenant_config = root / "tenant.json"
        self._write_values(self.identity_config, IDENTITY_VALUES)
        self._write_values(self.tenant_config, TENANT_VALUES)
        self.args = [
            "--config",
            str(self.identity_config),
            "--config",
            str(self.tenant_config),
            "--policy-dir",
            str(ROOT / "policies"),
            "--apply-report-only",
        ]
        config, _ = load_config([self.identity_config, self.tenant_config])
        self.desired = {}
        for _, document in load_policy_documents(ROOT / "policies"):
            resolved, missing = resolve_policy(document, config)
            self.assertFalse(missing)
            self.desired[resolved["metadata"]["id"]] = graph_payload(resolved)

    @staticmethod
    def _write_values(path: Path, values: dict) -> None:
        path.write_text(json.dumps({"values": values}), encoding="utf-8")

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_missing_apply_switch_performs_no_graph_operation(self, tenant, get_all, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args[:-1])
        self.assertEqual(2, result)
        tenant.assert_not_called()
        get_all.assert_not_called()
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_example_config_path_performs_no_graph_operation(self, tenant, get_all, request) -> None:
        args = [
            "--config",
            str(ROOT / "config" / "lab-identities.example.json"),
            "--config",
            str(ROOT / "config" / "tenant.example.json"),
            "--apply-report-only",
        ]
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(args)
        self.assertEqual(2, result)
        tenant.assert_not_called()
        get_all.assert_not_called()
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_known_example_ids_in_renamed_files_perform_no_graph_operation(self, tenant, get_all, request) -> None:
        root = Path(self.temp.name)
        self._write_values(self.identity_config, json.loads((ROOT / "config" / "lab-identities.example.json").read_text())["values"])
        self._write_values(self.tenant_config, json.loads((ROOT / "config" / "tenant.example.json").read_text())["values"])
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(2, result)
        tenant.assert_not_called()
        get_all.assert_not_called()
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_unresolved_variable_performs_no_graph_operation(self, tenant, get_all, request) -> None:
        self._write_values(self.tenant_config, {key: value for key, value in TENANT_VALUES.items() if key != "SENSITIVE_APP_ID"})
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(2, result)
        tenant.assert_not_called()
        get_all.assert_not_called()
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant", side_effect=GraphCliError("wrong tenant"))
    def test_wrong_tenant_performs_no_graph_operation(self, tenant, get_all, request) -> None:
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        tenant.assert_called_once_with(TENANT_ID)
        get_all.assert_not_called()
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_enabled_policy_overwrite_is_refused(self, _tenant, get_all, request) -> None:
        current = copy.deepcopy(self.desired["CA001"])
        current.update({"id": "aaaaaaaa-1111-4111-8111-111111111111", "state": "enabled"})
        get_all.return_value = [current]
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_hidden_tenant_setting_is_refused(self, _tenant, get_all, request) -> None:
        current = copy.deepcopy(self.desired["CA001"])
        current["id"] = "aaaaaaaa-1111-4111-8111-111111111111"
        current["sessionControls"] = {"signInFrequency": {"value": 1, "type": "hours"}}
        get_all.return_value = [current]
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_duplicate_policy_names_are_refused(self, _tenant, get_all, request) -> None:
        current = copy.deepcopy(self.desired["CA001"])
        current["id"] = "aaaaaaaa-1111-4111-8111-111111111111"
        duplicate = copy.deepcopy(current)
        duplicate["id"] = "bbbbbbbb-1111-4111-8111-111111111111"
        get_all.return_value = [current, duplicate]
        error = io.StringIO()
        with redirect_stderr(error):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        self.assertIn("Ambiguous current state", error.getvalue())
        request.assert_not_called()

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_valid_plan_only_updates_and_creates_intended_endpoints(self, tenant, get_all, request) -> None:
        ca001 = copy.deepcopy(self.desired["CA001"])
        ca001["id"] = "aaaaaaaa-1111-4111-8111-111111111111"
        ca001["conditions"]["users"]["excludeGroups"].remove(IDENTITY_VALUES["CA_MFA_EXCEPTION_GROUP_ID"])
        ca002 = copy.deepcopy(self.desired["CA002"])
        ca002["id"] = "aaaaaaaa-2222-4222-8222-222222222222"
        ca002["grantControls"]["authenticationStrength"].update(
            {"displayName": "Phishing-resistant MFA", "policyType": "builtIn", "allowedCombinations": ["fido2"]}
        )
        get_all.return_value = [ca001, ca002]

        def response(method, _url, _body=None):
            return {"id": "aaaaaaaa-3333-4333-8333-333333333333"} if method == "POST" else None

        request.side_effect = response
        with redirect_stdout(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(0, result)
        tenant.assert_called_once_with(TENANT_ID)
        self.assertEqual(2, request.call_count)
        methods = [entry.args[0] for entry in request.call_args_list]
        self.assertEqual(["PATCH", "POST"], methods)
        self.assertNotIn("DELETE", methods)
        self.assertEqual(
            f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{ca001['id']}",
            request.call_args_list[0].args[1],
        )
        self.assertEqual(self.desired["CA001"], request.call_args_list[0].args[2])
        self.assertEqual(self.desired["CA003"], request.call_args_list[1].args[2])

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all", return_value=[])
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_partial_deployment_reports_completed_and_stops(self, _tenant, _get_all, request) -> None:
        request.side_effect = [
            {"id": "aaaaaaaa-1111-4111-8111-111111111111"},
            GraphCliError("simulated second POST failure"),
        ]
        error = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(error):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        self.assertEqual(2, request.call_count)
        self.assertIn("PARTIAL DEPLOYMENT", error.getvalue())
        self.assertIn("Do not assume rollback or atomicity", error.getvalue())
        self.assertIn("fresh preview", error.getvalue())

    @patch("scripts.deploy_report_only.graph_request")
    @patch("scripts.deploy_report_only.graph_get_all")
    @patch("scripts.deploy_report_only.assert_graph_tenant")
    def test_malformed_config_fails_without_graph_operation(self, tenant, get_all, request) -> None:
        self.identity_config.write_text("{not json", encoding="utf-8")
        with redirect_stderr(io.StringIO()):
            result = deploy_report_only.main(self.args)
        self.assertEqual(1, result)
        tenant.assert_not_called()
        get_all.assert_not_called()
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
