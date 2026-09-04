from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.ca_policy import EXAMPLE_IDENTIFIERS, load_policy_documents


POLICY_RECORD_OWNER = "Zero Trust Identity & Conditional Access Lab"


class PolicyIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyIdentity:
    key: str
    tenant_id: str
    policy_id: str
    display_name: str


def canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise PolicyIdentityError(f"{field} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise PolicyIdentityError(f"{field} must be a canonical UUID string") from error
    canonical = str(parsed)
    if value.lower() != canonical:
        raise PolicyIdentityError(f"{field} must use canonical hyphenated UUID form")
    return canonical


def source_policy_names(policy_dir: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    for path, document in load_policy_documents(policy_dir):
        try:
            key = document["metadata"]["id"]
            name = document["graph"]["displayName"]
        except (KeyError, TypeError) as error:
            raise PolicyIdentityError(f"{path}: missing policy identity metadata") from error
        if key in names:
            raise PolicyIdentityError(f"{path}: duplicate source policy key {key}")
        names[key] = name
    return names


def load_policy_identity(record_path: Path, policy_key: str, policy_dir: Path) -> PolicyIdentity:
    if record_path.name.endswith(".example.json"):
        raise PolicyIdentityError("example policy identity records cannot authorize tenant changes")
    try:
        with record_path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyIdentityError(f"could not read policy identity record {record_path}: {error}") from error

    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        raise PolicyIdentityError("policy identity record schemaVersion must be 1")
    if document.get("example") is True:
        raise PolicyIdentityError("example policy identity records cannot authorize tenant changes")
    if document.get("owner") != POLICY_RECORD_OWNER:
        raise PolicyIdentityError(f"policy identity record owner must be exactly '{POLICY_RECORD_OWNER}'")

    tenant_id = canonical_uuid(document.get("tenantId"), "tenantId")
    policies = document.get("policies")
    if not isinstance(policies, dict) or policy_key not in policies:
        raise PolicyIdentityError(f"policy key {policy_key} is not present in the identity record")
    record = policies[policy_key]
    if not isinstance(record, dict):
        raise PolicyIdentityError(f"policy key {policy_key} must contain an object")
    policy_id = canonical_uuid(record.get("id"), f"policies.{policy_key}.id")
    display_name = record.get("displayName")

    expected_names = source_policy_names(policy_dir)
    if policy_key not in expected_names:
        raise PolicyIdentityError(f"policy key {policy_key} is not present in repository definitions")
    expected_name = expected_names[policy_key]
    if display_name != expected_name:
        raise PolicyIdentityError(
            f"policy record displayName mismatch for {policy_key}: expected {expected_name}, got {display_name}"
        )
    if tenant_id in EXAMPLE_IDENTIFIERS or policy_id in EXAMPLE_IDENTIFIERS:
        raise PolicyIdentityError("known example identifiers cannot authorize tenant changes")
    return PolicyIdentity(policy_key, tenant_id, policy_id, display_name)


def validate_current_policy(current: Any, identity: PolicyIdentity) -> str:
    if not isinstance(current, dict):
        raise PolicyIdentityError("Microsoft Graph returned a malformed policy object")
    current_id = current.get("id")
    current_name = current.get("displayName")
    current_state = current.get("state")
    if current_id != identity.policy_id:
        raise PolicyIdentityError(
            f"fetched policy ID mismatch: expected {identity.policy_id}, got {current_id}"
        )
    if current_name != identity.display_name:
        raise PolicyIdentityError(
            f"fetched policy displayName mismatch: expected {identity.display_name}, got {current_name}"
        )
    if not isinstance(current_state, str) or not current_state:
        raise PolicyIdentityError("fetched policy object has no valid state")
    return current_state
