#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ca_policy import example_identifier_keys, load_config
from src.graph_cli import GRAPH_ROOT, GraphCliError, assert_graph_tenant, graph_get_all


PERSONA_KEYS = {
    "LAB_STANDARD_USER_ID": "ordinary-user",
    "LAB_ADMIN_USER_ID": "administrator",
    "EMERGENCY_ACCESS_USER_1_ID": "emergency-access-1",
    "EMERGENCY_ACCESS_USER_2_ID": "emergency-access-2",
}


def _parse_timestamp(value: str) -> str:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone, for example 2026-09-04T08:00:00Z")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _minimal_event(event: dict, personas: dict[str, str], prefix: str) -> dict:
    policies = []
    for policy in event.get("appliedConditionalAccessPolicies", []) or []:
        if str(policy.get("displayName", "")).startswith(prefix):
            policies.append(
                {
                    "id": policy.get("id"),
                    "displayName": policy.get("displayName"),
                    "result": policy.get("result"),
                    "enforcedGrantControls": policy.get("enforcedGrantControls", []),
                }
            )
    device = event.get("deviceDetail") or {}
    status = event.get("status") or {}
    authentication_details = []
    for step in event.get("authenticationDetails", []) or []:
        authentication_details.append(
            {
                "authenticationStepDateTime": step.get("authenticationStepDateTime"),
                "authenticationMethod": step.get("authenticationMethod"),
                "authenticationMethodDetail": step.get("authenticationMethodDetail"),
                "succeeded": step.get("succeeded"),
                "authenticationStepResultDetail": step.get("authenticationStepResultDetail"),
                "authenticationStepRequirement": step.get("authenticationStepRequirement"),
            }
        )
    return {
        "signInId": event.get("id"),
        "createdDateTime": event.get("createdDateTime"),
        "persona": personas.get(event.get("userId"), "out-of-manifest"),
        "appDisplayName": event.get("appDisplayName"),
        "appId": event.get("appId"),
        "resourceDisplayName": event.get("resourceDisplayName"),
        "resourceId": event.get("resourceId"),
        "clientAppUsed": event.get("clientAppUsed"),
        "authenticationRequirement": event.get("authenticationRequirement"),
        "authenticationDetails": authentication_details,
        "conditionalAccessStatus": event.get("conditionalAccessStatus"),
        "status": {"errorCode": status.get("errorCode"), "failureReason": status.get("failureReason")},
        "device": {
            "deviceId": device.get("deviceId"),
            "operatingSystem": device.get("operatingSystem"),
            "browser": device.get("browser"),
            "isCompliant": device.get("isCompliant"),
            "isManaged": device.get("isManaged"),
            "trustType": device.get("trustType"),
        },
        "labPolicies": policies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect data-minimised sign-in evidence for lab policies.")
    parser.add_argument("--since", required=True, help="ISO-8601 timestamp with timezone")
    parser.add_argument("--until", help="ISO-8601 timestamp with timezone; defaults to now")
    parser.add_argument("--identity-config", type=Path, required=True)
    parser.add_argument("--tenant-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy-prefix", default="ZT-LAB-")
    args = parser.parse_args()
    try:
        since = _parse_timestamp(args.since)
        until = _parse_timestamp(args.until) if args.until else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        config, warnings = load_config([args.identity_config, args.tenant_config])
        if warnings:
            raise ValueError("Refusing evidence collection with an example configuration manifest")
        examples = example_identifier_keys(config)
        if examples:
            raise ValueError(f"Refusing known example identifiers in keys: {', '.join(examples)}")
        tenant_id = config.get("TENANT_ID")
        if not tenant_id:
            raise ValueError("TENANT_ID is required in tenant configuration")
        assert_graph_tenant(tenant_id)
        personas = {config[key]: label for key, label in PERSONA_KEYS.items() if key in config}
        query = urlencode({"$filter": f"createdDateTime ge {since} and createdDateTime le {until}"})
        events = graph_get_all(f"{GRAPH_ROOT}/auditLogs/signIns?{query}")
    except (ValueError, GraphCliError) as error:
        print(error, file=sys.stderr)
        return 1

    relevant = []
    for event in events:
        reduced = _minimal_event(event, personas, args.policy_prefix)
        if reduced["labPolicies"]:
            relevant.append(reduced)
    document = {
        "evidenceMetadata": {
            "type": "tenant-sign-in-observation",
            "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "windowStartUtc": since,
            "windowEndUtc": until,
            "source": "Microsoft Graph v1.0 /auditLogs/signIns",
            "tenantId": tenant_id,
            "policyPrefix": args.policy_prefix,
            "dataMinimisation": "UPN, user display name, IP address, and location omitted; shared user IDs mapped to personas; authentication steps limited to method/result fields",
            "interpretation": "Report-only results predict outcomes; only enabled-policy results plus an actual sign-in outcome demonstrate enforcement",
        },
        "events": relevant,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Collected {len(relevant)} relevant event(s) from {len(events)} sign-in record(s) into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
