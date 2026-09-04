from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from collections.abc import Sequence
from typing import Any


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


class GraphCliError(RuntimeError):
    pass


def _resolve_az() -> str:
    executable = shutil.which("az")
    if executable is None:
        raise GraphCliError("Azure CLI ('az') was not found. Install it and authenticate before tenant operations.")
    return executable


def _run_az(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    executable = _resolve_az()
    try:
        return subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise GraphCliError(f"Azure CLI could not be started from {executable}: {error}") from error


def _decode_json_response(completed: subprocess.CompletedProcess[str], operation: str) -> Any:
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise GraphCliError(f"{operation} returned malformed JSON: {error.msg}") from error


def graph_token_tenant_id() -> str:
    """Return the tenant in the current Microsoft Graph token without printing the token."""
    command = [
        "account",
        "get-access-token",
        "--resource-type",
        "ms-graph",
        "--query",
        "tenant",
        "--output",
        "tsv",
        "--only-show-errors",
    ]
    completed = _run_az(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unable to obtain a Microsoft Graph token"
        raise GraphCliError(detail)
    tenant_id = completed.stdout.strip()
    if not tenant_id:
        raise GraphCliError("Microsoft Graph token did not report a tenant ID")
    return tenant_id


def assert_graph_tenant(expected_tenant_id: str) -> str:
    actual = graph_token_tenant_id()
    if actual.lower() != expected_tenant_id.lower():
        raise GraphCliError(f"Tenant guard failed: Graph token tenant is {actual}, expected {expected_tenant_id}")
    return actual


def graph_request(method: str, url: str, body: dict[str, Any] | None = None) -> Any:
    command = ["rest", "--only-show-errors", "--method", method, "--url", url, "--output", "json"]
    if body is None:
        completed = _run_az(command)
    else:
        # az is commonly az.cmd on Windows. Passing JSON through a command-file
        # command line can reinterpret metacharacters, so transport it by file.
        with tempfile.TemporaryDirectory(prefix="zt-ca-graph-") as temp_dir:
            payload_path = Path(temp_dir) / "payload.json"
            payload_path.write_text(json.dumps(body, separators=(",", ":")), encoding="utf-8")
            command.extend(
                ["--headers", "Content-Type=application/json", "--body", f"@{payload_path}"]
            )
            completed = _run_az(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Azure CLI error"
        raise GraphCliError(f"Graph {method.upper()} failed: {detail}")
    return _decode_json_response(completed, f"Graph {method.upper()}")


def graph_get_all(url: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        response = graph_request("GET", next_url)
        if not isinstance(response, dict) or not isinstance(response.get("value"), list):
            raise GraphCliError("Graph collection response did not contain a value array")
        items.extend(response["value"])
        next_url = response.get("@odata.nextLink")
    return items
