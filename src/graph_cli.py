from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


class GraphCliError(RuntimeError):
    pass


def _require_az() -> None:
    if shutil.which("az") is None:
        raise GraphCliError("Azure CLI ('az') was not found. Install it and authenticate before tenant operations.")


def graph_token_tenant_id() -> str:
    """Return the tenant in the current Microsoft Graph token without printing the token."""
    _require_az()
    command = [
        "az",
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
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
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
    _require_az()
    command = ["az", "rest", "--only-show-errors", "--method", method, "--url", url, "--output", "json"]
    if body is not None:
        command.extend(["--headers", "Content-Type=application/json", "--body", json.dumps(body, separators=(",", ":"))])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Azure CLI error"
        raise GraphCliError(f"Graph {method.upper()} failed: {detail}")
    output = completed.stdout.strip()
    return json.loads(output) if output else None


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
