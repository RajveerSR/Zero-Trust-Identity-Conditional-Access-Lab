from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from src.graph_cli import GraphCliError, graph_get_all, graph_request, graph_token_tenant_id


AZ_CMD = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"


def completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class GraphCliTests(unittest.TestCase):
    @patch("src.graph_cli.subprocess.run")
    @patch("src.graph_cli.shutil.which", return_value=AZ_CMD)
    def test_resolved_windows_command_path_is_executed(self, _which, run) -> None:
        run.return_value = completed(stdout="tenant-id\n")
        self.assertEqual("tenant-id", graph_token_tenant_id())
        command = run.call_args.args[0]
        self.assertEqual(AZ_CMD, command[0])
        self.assertEqual(["account", "get-access-token"], command[1:3])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    @patch("src.graph_cli.shutil.which", return_value=None)
    def test_missing_cli_is_a_clear_graph_error(self, _which) -> None:
        with self.assertRaisesRegex(GraphCliError, "Azure CLI .* was not found"):
            graph_token_tenant_id()

    @patch("src.graph_cli.subprocess.run", side_effect=OSError("not executable"))
    @patch("src.graph_cli.shutil.which", return_value=AZ_CMD)
    def test_process_launch_failure_is_a_clear_graph_error(self, _which, _run) -> None:
        with self.assertRaisesRegex(GraphCliError, "could not be started"):
            graph_token_tenant_id()

    @patch("src.graph_cli.subprocess.run")
    @patch("src.graph_cli.shutil.which", return_value=AZ_CMD)
    def test_json_body_uses_temporary_payload_file(self, _which, run) -> None:
        observed = {}

        def inspect_payload(command, **_kwargs):
            body_argument = command[command.index("--body") + 1]
            self.assertTrue(body_argument.startswith("@"))
            payload_path = body_argument[1:]
            with open(payload_path, encoding="utf-8") as handle:
                observed.update(json.load(handle))
            return completed(stdout='{"id":"created"}')

        run.side_effect = inspect_payload
        response = graph_request("POST", "https://graph.example/policies", {"displayName": "A & B"})
        self.assertEqual({"displayName": "A & B"}, observed)
        self.assertEqual("created", response["id"])
        self.assertEqual(AZ_CMD, run.call_args.args[0][0])

    @patch("src.graph_cli.subprocess.run", return_value=completed(stdout="not-json"))
    @patch("src.graph_cli.shutil.which", return_value=AZ_CMD)
    def test_malformed_json_is_a_clear_graph_error(self, _which, _run) -> None:
        with self.assertRaisesRegex(GraphCliError, "Graph GET returned malformed JSON"):
            graph_request("GET", "https://graph.example/policies")

    @patch("src.graph_cli.subprocess.run", return_value=completed(stderr="permission denied", returncode=1))
    @patch("src.graph_cli.shutil.which", return_value=AZ_CMD)
    def test_nonzero_cli_result_is_a_clear_graph_error(self, _which, _run) -> None:
        with self.assertRaisesRegex(GraphCliError, "Graph PATCH failed: permission denied"):
            graph_request("PATCH", "https://graph.example/policies/id", {"state": "disabled"})

    @patch("src.graph_cli.graph_request")
    def test_pagination_collects_all_pages(self, request) -> None:
        request.side_effect = [
            {"value": [{"id": "one"}], "@odata.nextLink": "https://graph.example/page2"},
            {"value": [{"id": "two"}]},
        ]
        self.assertEqual([{"id": "one"}, {"id": "two"}], graph_get_all("https://graph.example/page1"))
        self.assertEqual(2, request.call_count)

    @patch("src.graph_cli.graph_request", return_value={"unexpected": []})
    def test_malformed_collection_fails(self, _request) -> None:
        with self.assertRaisesRegex(GraphCliError, "did not contain a value array"):
            graph_get_all("https://graph.example/page1")


if __name__ == "__main__":
    unittest.main()
