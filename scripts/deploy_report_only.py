#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import (
    REPORT_ONLY_STATE,
    classify_change,
    current_policy_map,
    graph_payload,
    example_identifier_keys,
    extra_paths,
    load_config,
    load_policy_documents,
    normalize_graph_policy,
    resolve_policy,
    validate_collection,
)
from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_get_all, graph_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or update only report-only Conditional Access policies.")
    parser.add_argument("--config", type=Path, action="append", required=True)
    parser.add_argument("--policy-dir", type=Path, default=ROOT / "policies")
    parser.add_argument("--apply-report-only", action="store_true", help="Required mutation guard")
    args = parser.parse_args(argv)
    if not args.apply_report_only:
        print("Refusing to mutate: run preview_changes.py first, then pass --apply-report-only.", file=sys.stderr)
        return 2
    if any(path.name.endswith(".example.json") for path in args.config):
        print("Refusing to deploy with example configuration files.", file=sys.stderr)
        return 2

    completed_changes: list[str] = []
    attempted_change: str | None = None
    try:
        config, _ = load_config(args.config)
        examples = example_identifier_keys(config)
        if examples:
            print(f"Refusing known example identifiers in keys: {', '.join(examples)}", file=sys.stderr)
            return 2
        resolved_documents = []
        for path, document in load_policy_documents(args.policy_dir):
            resolved, missing = resolve_policy(document, config)
            if missing:
                print(f"{path}: unresolved keys: {', '.join(sorted(missing))}", file=sys.stderr)
                return 2
            resolved_documents.append((path, resolved))
        errors = [
            issue
            for issue in validate_collection(resolved_documents, config.get("EMERGENCY_ACCESS_GROUP_ID"))
            if issue.severity == "ERROR"
        ]
        if errors:
            print("\n".join(str(item) for item in errors), file=sys.stderr)
            return 2

        tenant_id = config.get("TENANT_ID")
        if not tenant_id:
            raise RuntimeError("TENANT_ID is required in configuration")
        assert_graph_tenant(tenant_id)
        existing_items = graph_get_all(f"{GRAPH_ROOT}/identity/conditionalAccess/policies")
        existing = current_policy_map(existing_items)
        plan = []
        for _, document in resolved_documents:
            desired = graph_payload(document)
            if desired.get("state") != REPORT_ONLY_STATE:
                raise RuntimeError(f"Guard failure: {desired.get('displayName')} is not report-only")
            action = classify_change(desired, existing)
            current = existing.get(desired["displayName"])
            if current and action in {"UPDATE", "UNCHANGED"} and not current.get("id"):
                raise RuntimeError(f"Current policy {desired['displayName']} has no Graph object ID")
            if action == "UPDATE" and current and current.get("state") == "enabled":
                raise RuntimeError(
                    f"Refusing to overwrite enabled policy {desired['displayName']}; investigate name ownership and disable explicitly"
                )
            if action == "UPDATE" and current:
                extras = extra_paths(normalize_graph_policy(current), normalize_graph_policy(desired))
                if extras:
                    raise RuntimeError(
                        f"Refusing partial update of {desired['displayName']}; tenant has out-of-source settings at: "
                        + ", ".join(extras)
                    )
            plan.append((action, desired, current))

        for action, desired, current in plan:
            if action == "CREATE":
                attempted_change = f"CREATE {desired['displayName']}"
                created = graph_request("POST", f"{GRAPH_ROOT}/identity/conditionalAccess/policies", desired)
                if not isinstance(created, dict) or not created.get("id"):
                    raise GraphCliError(
                        f"Graph POST returned no policy ID for {desired['displayName']}; mutation outcome is uncertain"
                    )
                completed_changes.append(attempted_change)
                print(f"CREATED report-only {desired['displayName']} ({created['id']})")
            elif action == "UPDATE":
                attempted_change = f"UPDATE {desired['displayName']} ({current['id']})"
                graph_request("PATCH", f"{GRAPH_ROOT}/identity/conditionalAccess/policies/{current['id']}", desired)
                completed_changes.append(attempted_change)
                print(f"UPDATED report-only {desired['displayName']} ({current['id']})")
            else:
                print(f"UNCHANGED {desired['displayName']} ({current.get('id', 'unknown id')})")
            attempted_change = None
    except (GraphCliError, RuntimeError, ValueError, OSError) as error:
        print(error, file=sys.stderr)
        if completed_changes:
            print(
                "PARTIAL DEPLOYMENT: completed before failure: " + "; ".join(completed_changes),
                file=sys.stderr,
            )
        if attempted_change:
            print(f"Last attempted change: {attempted_change}; its outcome may require verification.", file=sys.stderr)
        if completed_changes or attempted_change:
            print(
                "Do not assume rollback or atomicity. Export current policies again and run a fresh preview before recovery or retry.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
