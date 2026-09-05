import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from src.graph_cli import graph_get_all, graph_request
from scripts import collect_signin_evidence as collector

HEADERS = {"Prefer": "include-unknown-enum-members"}

class ReportOnlyEvidenceTests(unittest.TestCase):
    @patch("src.graph_cli._run_az")
    def test_preference_reaches_cli_with_json_payload_content_type(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout='{"id":"one"}', stderr='')
        graph_request("POST", "https://graph.microsoft.com/v1.0/example", {"test":True}, headers=HEADERS)
        command = run.call_args.args[0]
        self.assertEqual(1, command.count("--headers"))
        self.assertIn("Prefer=include-unknown-enum-members", command)
        self.assertIn("Content-Type=application/json", command)

    @patch("src.graph_cli.graph_request")
    def test_every_page_retains_enum_preference(self, request):
        request.side_effect = [{"value":[], "@odata.nextLink":"https://graph.microsoft.com/v1.0/next"}, {"value":[{"result":"reportOnlySuccess"}]}]
        self.assertEqual([{"result":"reportOnlySuccess"}], graph_get_all("https://graph.microsoft.com/v1.0/signins", headers=HEADERS))
        self.assertEqual(2, request.call_count)
        for call in request.call_args_list:
            self.assertEqual(HEADERS, call.kwargs["headers"])

    @patch("scripts.collect_signin_evidence.assert_graph_tenant")
    @patch("scripts.collect_signin_evidence.graph_get_all")
    def test_collector_requests_report_only_values_and_exposes_missing_details(self, get_all, tenant):
        tenant.return_value = "d0000000-1111-4111-8111-111111111111"
        get_all.return_value = [
            {"id":"missing-details"},
            {"id":"observed", "appliedConditionalAccessPolicies":[{"id":"ca1", "displayName":"ZT-LAB-CA001-Test", "result":"reportOnlySuccess"}]}
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            config = root / "tenant.json"
            output = root / "evidence.json"
            identity.write_text('{"values": {}}', encoding="utf-8")
            config.write_text(json.dumps({"values":{"TENANT_ID":tenant.return_value}}), encoding="utf-8")
            with redirect_stdout(io.StringIO()) as log:
                result = collector.main(["--since","2026-09-05T09:00:00Z", "--identity-config",str(identity), "--tenant-config",str(config), "--output",str(output)])
            self.assertEqual(0,result)
            self.assertEqual(HEADERS,get_all.call_args.kwargs["headers"])
            saved = json.loads(output.read_text())
            self.assertEqual(1,saved["evidenceMetadata"]["recordsMissingConditionalAccessDetails"])
            self.assertEqual("reportOnlySuccess",saved["events"][0]["labPolicies"][0]["result"])
            self.assertIn("omit Conditional Access details",log.getvalue())
