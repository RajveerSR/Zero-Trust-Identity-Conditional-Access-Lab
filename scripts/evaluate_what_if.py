#!/usr/bin/env python3
"""Evaluate a user/application scenario without changing Conditional Access."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_request


def validate_request(document: dict) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "signInIdentity", "signInContext", "signInConditions", "appliedPoliciesOnly"
    }:
        raise ValueError("Supply identity, application context, conditions and appliedPoliciesOnly.")
    identity = document["signInIdentity"]
    context = document["signInContext"]
    if not isinstance(identity, dict) or set(identity) != {"@odata.type", "userId"}:
        raise ValueError("Only an explicit user identity is supported.")
    if identity["@odata.type"] != "#microsoft.graph.userSignIn":
        raise ValueError("Expected a userSignIn identity.")
    UUID(identity["userId"])
    if not isinstance(context, dict) or set(context) != {"@odata.type", "includeApplications"}:
        raise ValueError("Only explicit application context is supported.")
    if context["@odata.type"] != "#microsoft.graph.applicationContext":
        raise ValueError("Expected applicationContext.")
    apps = context["includeApplications"]
    if not isinstance(apps, list) or len(apps) != 1:
        raise ValueError("Evaluate exactly one resource application ID per evidence record.")
    UUID(apps[0])
    if document["appliedPoliciesOnly"] is not False:
        raise ValueError("Include nonapplicable policies by setting appliedPoliciesOnly to false.")
    conditions = document["signInConditions"]
    if not isinstance(conditions, dict) or not conditions.get("clientAppType") or not conditions.get("devicePlatform"):
        raise ValueError("Provide explicit clientAppType and devicePlatform conditions.")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("Output already exists; choose a new evidence path.")
        UUID(args.expected_tenant_id)
        request = validate_request(json.loads(args.input.read_text(encoding="utf-8-sig")))
        tenant = assert_graph_tenant(args.expected_tenant_id)
        # This POST invokes the documented simulation action; it does not create a policy.
        response = graph_request("POST", f"{GRAPH_ROOT}/identity/conditionalAccess/evaluate", request)
        if not isinstance(response, dict) or not isinstance(response.get("value"), list):
            raise ValueError("What If returned no result collection; no successful evidence saved.")
        if response.get("@odata.nextLink"):
            raise ValueError("Unexpected paginated result; refusing incomplete evidence.")
        result = {
            "evidenceMetadata": {
                "type": "tenant-what-if-simulation",
                "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
                "tenantId": tenant,
                "source": "Microsoft Graph v1.0 /identity/conditionalAccess/evaluate",
                "interpretation": "Simulated applicability only; input device/risk values are assumptions, not observed state. Does not prove authentication or enforcement.",
            },
            "request": request,
            "value": response["value"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Saved {len(response['value'])} What If result(s): {args.output}")
        return 0
    except (GraphCliError, ValueError, TypeError, AttributeError, OSError) as error:
        print(f"What If failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
