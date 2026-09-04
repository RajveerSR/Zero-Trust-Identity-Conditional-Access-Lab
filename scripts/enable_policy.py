#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import REPORT_ONLY_STATE
from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_request


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicitly enable one tested report-only policy.")
    parser.add_argument("--policy-id", required=True, help="Microsoft Graph Conditional Access policy object ID")
    parser.add_argument("--change-reference", required=True, help="Recorded approval/change reference")
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--confirm", required=True, help="Must equal ENABLE:<policy-id>")
    args = parser.parse_args()
    try:
        uuid.UUID(args.policy_id)
    except ValueError:
        print("--policy-id must be a UUID", file=sys.stderr)
        return 2
    if args.confirm != f"ENABLE:{args.policy_id}":
        print("Confirmation mismatch; no change made.", file=sys.stderr)
        return 2
    try:
        assert_graph_tenant(args.expected_tenant_id)
        url = f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{args.policy_id}"
        current = graph_request("GET", url)
        if current.get("state") != REPORT_ONLY_STATE:
            raise RuntimeError(f"Policy state is {current.get('state')}, expected {REPORT_ONLY_STATE}")
        graph_request("PATCH", url, {"state": "enabled"})
        print(f"ENABLED {current.get('displayName')} ({args.policy_id}); change reference: {args.change_reference}")
    except (GraphCliError, RuntimeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
