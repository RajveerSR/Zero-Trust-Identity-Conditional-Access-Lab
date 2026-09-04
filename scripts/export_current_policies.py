#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_get_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export current Conditional Access policies (read-only).")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    args = parser.parse_args(argv)
    try:
        tenant_id = assert_graph_tenant(args.expected_tenant_id)
        policies = graph_get_all(f"{GRAPH_ROOT}/identity/conditionalAccess/policies")
    except GraphCliError as error:
        print(error, file=sys.stderr)
        return 1
    document = {
        "evidenceMetadata": {
            "type": "tenant-configuration-export",
            "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "source": "Microsoft Graph v1.0 /identity/conditionalAccess/policies",
            "tenantId": tenant_id,
            "claim": "Configuration snapshot only; does not prove evaluation or enforcement"
        },
        "value": policies,
    }
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"Unable to write policy export: {error}", file=sys.stderr)
        return 1
    print(f"Exported {len(policies)} policies to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
