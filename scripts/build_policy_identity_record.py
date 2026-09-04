#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import read_json
from src.policy_identity import POLICY_RECORD_OWNER, PolicyIdentityError, canonical_uuid, source_policy_names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a tenant-bound lab policy identity record from a postdeployment policy export."
    )
    parser.add_argument("--policy-export", type=Path, required=True)
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policies")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise PolicyIdentityError(f"refusing to overwrite existing identity record {args.output}")
        exported = read_json(args.policy_export)
        if not isinstance(exported, dict):
            raise PolicyIdentityError("policy export must be a JSON object")
        metadata = exported.get("evidenceMetadata")
        if not isinstance(metadata, dict) or metadata.get("type") != "tenant-configuration-export":
            raise PolicyIdentityError("policy export is missing tenant-configuration-export metadata")
        tenant_id = canonical_uuid(metadata.get("tenantId"), "evidenceMetadata.tenantId")
        items = exported.get("value")
        if not isinstance(items, list):
            raise PolicyIdentityError("policy export must contain a value array")

        by_name: dict[str, list[dict]] = {}
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("displayName"), str):
                by_name.setdefault(item["displayName"], []).append(item)

        policies = {}
        for key, expected_name in sorted(source_policy_names(args.policy_dir).items()):
            matches = by_name.get(expected_name, [])
            if len(matches) != 1:
                raise PolicyIdentityError(
                    f"expected exactly one exported policy named {expected_name}, found {len(matches)}"
                )
            policy_id = canonical_uuid(matches[0].get("id"), f"exported {key} policy ID")
            policies[key] = {"id": policy_id, "displayName": expected_name}

        record = {
            "schemaVersion": 1,
            "owner": POLICY_RECORD_OWNER,
            "example": False,
            "tenantId": tenant_id,
            "sourceExport": str(args.policy_export),
            "sourceCapturedAtUtc": metadata.get("capturedAtUtc"),
            "policies": policies,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"WROTE tenant-bound identity record for {len(policies)} policies to {args.output}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
