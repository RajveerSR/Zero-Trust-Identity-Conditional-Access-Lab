#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import REPORT_ONLY_STATE
from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_request
from src.policy_identity import PolicyIdentityError, load_policy_identity, validate_current_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicitly enable one tested report-only policy.")
    parser.add_argument("--policy-record", type=Path, required=True, help="Tenant-bound lab policy identity record")
    parser.add_argument("--policy-key", choices=("CA001", "CA002", "CA003"), required=True)
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policies")
    parser.add_argument("--change-reference", required=True, help="Recorded approval/change reference")
    parser.add_argument("--confirm", required=True, help="Must equal ENABLE:<policy-key>:<policy-id>")
    args = parser.parse_args(argv)
    try:
        identity = load_policy_identity(args.policy_record, args.policy_key, args.policy_dir)
        if args.confirm != f"ENABLE:{identity.key}:{identity.policy_id}":
            raise PolicyIdentityError("confirmation mismatch; no change made")
        assert_graph_tenant(identity.tenant_id)
        url = f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{identity.policy_id}"
        current = graph_request("GET", url)
        current_state = validate_current_policy(current, identity)
        if current_state != REPORT_ONLY_STATE:
            raise PolicyIdentityError(f"policy state is {current_state}, expected {REPORT_ONLY_STATE}")
        print(
            f"TARGET tenant={identity.tenant_id} key={identity.key} id={identity.policy_id} "
            f"displayName={identity.display_name} currentState={current_state}; action=ENABLE"
        )
        graph_request("PATCH", url, {"state": "enabled"})
        print(f"ENABLED {identity.display_name} ({identity.policy_id}); change reference: {args.change_reference}")
    except (GraphCliError, PolicyIdentityError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
