#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_request


def main() -> int:
    parser = argparse.ArgumentParser(description="Emergency disable of one Conditional Access policy.")
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--incident-reference", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--confirm", required=True, help="Must equal DISABLE:<policy-id>")
    args = parser.parse_args()
    try:
        uuid.UUID(args.policy_id)
    except ValueError:
        print("--policy-id must be a UUID", file=sys.stderr)
        return 2
    if args.confirm != f"DISABLE:{args.policy_id}":
        print("Confirmation mismatch; no change made.", file=sys.stderr)
        return 2
    try:
        assert_graph_tenant(args.expected_tenant_id)
        url = f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{args.policy_id}"
        current = graph_request("GET", url)
        graph_request("PATCH", url, {"state": "disabled"})
        print(f"DISABLED {current.get('displayName')} ({args.policy_id}); incident: {args.incident_reference}")
    except GraphCliError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
