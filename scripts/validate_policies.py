#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import load_config, load_policy_documents, resolve_policy, select_policy_documents, validate_collection


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Conditional Access policy definitions locally.")
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policies")
    parser.add_argument("--policy-id", action="append", choices=("CA001", "CA002", "CA003"), help="Validate only the selected policy; repeat for more than one")
    parser.add_argument("--config", type=Path, action="append", default=[])
    parser.add_argument("--use-example-config", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_paths = list(args.config)
    if args.use_example_config:
        config_paths.extend(
            [ROOT / "config" / "lab-identities.example.json", ROOT / "config" / "tenant.example.json"]
        )
    documents = select_policy_documents(load_policy_documents(args.policy_dir), args.policy_id)
    expected_ids = set(args.policy_id) if args.policy_id else None
    issues = validate_collection(documents, expected_policy_ids=expected_ids)

    if config_paths:
        config, warnings = load_config(config_paths)
        for warning in warnings:
            print(f"WARNING: {warning}")
        resolved_documents = []
        for path, document in documents:
            resolved, missing = resolve_policy(document, config)
            if missing:
                for key in sorted(missing):
                    print(f"ERROR: {path}: unresolved configuration key {key}")
            resolved_documents.append((path, resolved))
        issues.extend(validate_collection(resolved_documents, config.get("EMERGENCY_ACCESS_GROUP_ID"), expected_ids))

    for issue in issues:
        print(issue)
    errors = [issue for issue in issues if issue.severity == "ERROR"]
    if errors:
        print(f"FAILED: {len(errors)} validation error(s)")
        return 1
    print(f"OK: {len(documents)} report-only policy definitions passed local validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
