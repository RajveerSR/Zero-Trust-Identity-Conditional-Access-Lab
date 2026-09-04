#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import (
    canonical_json,
    classify_change,
    current_policy_map,
    graph_payload,
    load_config,
    load_policy_documents,
    normalize_graph_policy,
    read_json,
    resolve_policy,
    validate_collection,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preview Conditional Access creates and updates without mutation.")
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policies")
    parser.add_argument("--config", type=Path, action="append", default=[])
    parser.add_argument("--use-example-config", action="store_true")
    parser.add_argument("--current", type=Path, help="Graph policy export; omission treats the tenant as empty")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config_paths = list(args.config)
    if args.use_example_config:
        config_paths.extend(
            [ROOT / "config" / "lab-identities.example.json", ROOT / "config" / "tenant.example.json"]
        )
    if not config_paths:
        raise SystemExit("Provide --config at least twice (identity and tenant manifests), or use --use-example-config")

    try:
        config, warnings = load_config(config_paths)
        for warning in warnings:
            print(f"WARNING: {warning}")
        raw_documents = load_policy_documents(args.policy_dir)
        resolved_documents = []
        missing_any: set[str] = set()
        for path, document in raw_documents:
            resolved, missing = resolve_policy(document, config)
            resolved_documents.append((path, resolved))
            missing_any.update(missing)
        if missing_any:
            print(f"Unresolved configuration keys: {', '.join(sorted(missing_any))}", file=sys.stderr)
            return 2
        errors = [
            item
            for item in validate_collection(resolved_documents, config.get("EMERGENCY_ACCESS_GROUP_ID"))
            if item.severity == "ERROR"
        ]
        if errors:
            print("\n".join(str(item) for item in errors), file=sys.stderr)
            return 2
        current = current_policy_map(read_json(args.current)) if args.current else {}
    except (OSError, ValueError) as error:
        print(f"Unable to prepare change preview: {error}", file=sys.stderr)
        return 1
    print("\nConditional Access change preview (read-only)\n")
    print(f"{'ACTION':<10} {'POLICY':<7} DISPLAY NAME")
    print(f"{'-' * 10} {'-' * 7} {'-' * 52}")
    plans: list[tuple[str, dict, dict | None]] = []
    for _, document in resolved_documents:
        desired = graph_payload(document)
        action = classify_change(desired, current)
        print(f"{action:<10} {document['metadata']['id']:<7} {desired['displayName']}")
        plans.append((action, desired, current.get(desired["displayName"])))

    for action, desired, existing in plans:
        if action != "UPDATE" or existing is None:
            continue
        print(f"\nDiff for {desired['displayName']} (current -> desired):")
        before = canonical_json(normalize_graph_policy(existing)).splitlines()
        after = canonical_json(normalize_graph_policy(desired)).splitlines()
        for line in difflib.unified_diff(before, after, fromfile="current", tofile="desired", lineterm=""):
            print(line)
    print("\nNo changes were made. Repository definitions remain report-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
