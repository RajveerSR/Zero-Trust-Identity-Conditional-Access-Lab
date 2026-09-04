from __future__ import annotations

import copy
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPORT_ONLY_STATE = "enabledForReportingButNotEnforced"
TOKEN_PATTERN = re.compile(r"^\$\{([A-Z0-9_]+)\}$")
REQUIRED_METADATA = (
    "id",
    "purpose",
    "scope",
    "exclusions",
    "controls",
    "prerequisites",
    "expectedUserImpact",
    "owner",
    "verificationStatus",
)
SERVER_MANAGED_FIELDS = {
    "id",
    "createdDateTime",
    "modifiedDateTime",
    "templateId",
    "partialEnablementStrategy",
}
AUTH_STRENGTH_READ_ONLY_FIELDS = {
    "displayName",
    "description",
    "policyType",
    "requirementsSatisfied",
    "allowedCombinations",
    "createdDateTime",
    "modifiedDateTime",
}
EXAMPLE_IDENTIFIERS = {
    f"{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}" for digit in "123456789ab"
}


@dataclass(frozen=True)
class PolicyIssue:
    severity: str
    policy: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity}: {self.policy}: {self.message}"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_config(paths: Iterable[Path]) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    warnings: list[str] = []
    for path in paths:
        document = read_json(path)
        if not isinstance(document.get("values"), dict):
            raise ValueError(f"{path}: expected an object named 'values'")
        overlap = set(values).intersection(document["values"])
        if overlap:
            raise ValueError(f"{path}: duplicate configuration keys: {', '.join(sorted(overlap))}")
        values.update(document["values"])
        if path.name.endswith(".example.json"):
            warnings.append(f"{path} contains example identifiers; never use it for tenant deployment")
    return values, warnings


def example_identifier_keys(config: dict[str, str]) -> list[str]:
    return sorted(key for key, value in config.items() if str(value).lower() in EXAMPLE_IDENTIFIERS)


def _replace_tokens(value: Any, config: dict[str, str], missing: set[str]) -> Any:
    if isinstance(value, str):
        match = TOKEN_PATTERN.match(value)
        if not match:
            return value
        key = match.group(1)
        if key not in config:
            missing.add(key)
            return value
        return config[key]
    if isinstance(value, list):
        return [_replace_tokens(item, config, missing) for item in value]
    if isinstance(value, dict):
        return {key: _replace_tokens(item, config, missing) for key, item in value.items()}
    return value


def resolve_policy(document: dict[str, Any], config: dict[str, str]) -> tuple[dict[str, Any], set[str]]:
    missing: set[str] = set()
    resolved = _replace_tokens(copy.deepcopy(document), config, missing)
    return resolved, missing


def load_policy_documents(policy_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    result: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(policy_dir.glob("*.json")):
        result.append((path, read_json(path)))
    if not result:
        raise ValueError(f"No policy JSON files found in {policy_dir}")
    return result


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)


def validate_policy(
    document: dict[str, Any],
    source: str = "policy",
    expected_emergency_group: str | None = None,
) -> list[PolicyIssue]:
    issues: list[PolicyIssue] = []
    metadata = document.get("metadata")
    graph = document.get("graph")
    policy_name = metadata.get("id", source) if isinstance(metadata, dict) else source

    if document.get("schemaVersion") != 1:
        issues.append(PolicyIssue("ERROR", policy_name, "schemaVersion must be 1"))
    if not isinstance(metadata, dict):
        issues.append(PolicyIssue("ERROR", policy_name, "metadata must be an object"))
        return issues
    for field in REQUIRED_METADATA:
        if not metadata.get(field):
            issues.append(PolicyIssue("ERROR", policy_name, f"metadata.{field} is required"))
    if not isinstance(metadata.get("prerequisites"), list):
        issues.append(PolicyIssue("ERROR", policy_name, "metadata.prerequisites must be a list"))
    if not isinstance(graph, dict):
        issues.append(PolicyIssue("ERROR", policy_name, "graph must be an object"))
        return issues

    expected_display_prefix = f"ZT-LAB-{policy_name}-"
    if not str(graph.get("displayName", "")).startswith(expected_display_prefix):
        issues.append(PolicyIssue("ERROR", policy_name, f"displayName must start with {expected_display_prefix}"))
    if graph.get("state") != REPORT_ONLY_STATE:
        issues.append(PolicyIssue("ERROR", policy_name, "repository definitions must remain report-only"))

    conditions = graph.get("conditions", {})
    users = conditions.get("users", {})
    apps = conditions.get("applications", {})
    if not users.get("includeGroups"):
        issues.append(PolicyIssue("ERROR", policy_name, "conditions.users.includeGroups must be non-empty"))
    if "All" in users.get("includeUsers", []):
        issues.append(PolicyIssue("ERROR", policy_name, "pilot policies must not target All users"))
    if not apps.get("includeApplications"):
        issues.append(PolicyIssue("ERROR", policy_name, "at least one target application is required"))
    if conditions.get("clientAppTypes") != ["all"]:
        issues.append(PolicyIssue("ERROR", policy_name, "clientAppTypes must explicitly cover all clients"))

    excluded = users.get("excludeGroups", [])
    expected_exclusion = expected_emergency_group or "${EMERGENCY_ACCESS_GROUP_ID}"
    if expected_exclusion not in excluded:
        issues.append(PolicyIssue("ERROR", policy_name, "an emergency-access group exclusion is required"))
    for group_id in users.get("includeGroups", []) + excluded:
        if not (TOKEN_PATTERN.match(str(group_id)) or _is_uuid(group_id)):
            issues.append(PolicyIssue("ERROR", policy_name, f"invalid group object ID: {group_id}"))
    overlap = set(users.get("includeGroups", [])).intersection(excluded)
    if overlap:
        issues.append(PolicyIssue("ERROR", policy_name, "a group cannot be both included and excluded"))
    for app_id in apps.get("includeApplications", []):
        if app_id != "All" and not (TOKEN_PATTERN.match(str(app_id)) or _is_uuid(app_id)):
            issues.append(PolicyIssue("ERROR", policy_name, f"invalid application ID: {app_id}"))

    grants = graph.get("grantControls", {})
    if grants.get("operator") != "OR":
        issues.append(PolicyIssue("ERROR", policy_name, "single-control policies use grantControls.operator OR"))
    if "block" in grants.get("builtInControls", []):
        issues.append(PolicyIssue("ERROR", policy_name, "block is outside this first-version policy set"))

    if policy_name == "CA001" and grants.get("builtInControls") != ["mfa"]:
        issues.append(PolicyIssue("ERROR", policy_name, "CA001 must require the mfa built-in control"))
    if policy_name == "CA002":
        strength_id = grants.get("authenticationStrength", {}).get("id")
        if not (strength_id == "${PHISHING_RESISTANT_AUTH_STRENGTH_ID}" or _is_uuid(strength_id)):
            issues.append(PolicyIssue("ERROR", policy_name, "CA002 requires a valid authentication-strength ID"))
    if policy_name == "CA003":
        if grants.get("builtInControls") != ["compliantDevice"]:
            issues.append(PolicyIssue("ERROR", policy_name, "CA003 must require compliantDevice"))
        if "unverified" not in str(metadata.get("verificationStatus", "")):
            issues.append(PolicyIssue("ERROR", policy_name, "device scenario must remain labelled unverified without evidence"))
        if conditions.get("platforms", {}).get("includePlatforms") != ["windows"]:
            issues.append(PolicyIssue("ERROR", policy_name, "CA003 v0.1 must remain scoped to the Windows device pilot"))

    for value in _walk_strings(document):
        if any(secret_word in value.lower() for secret_word in ("client_secret", "password=", "bearer ey")):
            issues.append(PolicyIssue("ERROR", policy_name, "possible credential material detected"))
    return issues


def validate_collection(
    documents: list[tuple[Path, dict[str, Any]]],
    expected_emergency_group: str | None = None,
) -> list[PolicyIssue]:
    issues: list[PolicyIssue] = []
    ids: set[str] = set()
    names: set[str] = set()
    for path, document in documents:
        issues.extend(validate_policy(document, str(path), expected_emergency_group))
        metadata = document.get("metadata", {})
        graph = document.get("graph", {})
        policy_id = metadata.get("id")
        display_name = graph.get("displayName")
        if policy_id in ids:
            issues.append(PolicyIssue("ERROR", str(path), f"duplicate policy metadata ID {policy_id}"))
        if display_name in names:
            issues.append(PolicyIssue("ERROR", str(path), f"duplicate displayName {display_name}"))
        ids.add(policy_id)
        names.add(display_name)
    expected = {"CA001", "CA002", "CA003"}
    if ids != expected:
        issues.append(PolicyIssue("ERROR", "collection", f"expected policy IDs {sorted(expected)}, got {sorted(ids)}"))
    return issues


def graph_payload(document: dict[str, Any]) -> dict[str, Any]:
    """Return only the Graph API body; repository metadata never leaves this boundary."""
    return copy.deepcopy(document["graph"])


def normalize_graph_policy(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(policy)
    for field in SERVER_MANAGED_FIELDS:
        normalized.pop(field, None)
    strength = normalized.get("grantControls", {}).get("authenticationStrength")
    if isinstance(strength, dict):
        for field in AUTH_STRENGTH_READ_ONLY_FIELDS:
            strength.pop(field, None)

    def prune_empty(value: Any) -> Any:
        if isinstance(value, dict):
            result = {key: prune_empty(item) for key, item in value.items()}
            return {key: item for key, item in result.items() if item not in (None, [], {})}
        if isinstance(value, list):
            result = [prune_empty(item) for item in value]
            return sorted(result) if all(isinstance(item, str) for item in result) else result
        return value

    return prune_empty(normalized)


def extra_paths(current: Any, desired: Any, prefix: str = "") -> list[str]:
    """Find non-empty current settings absent from source; PATCH omission would retain them."""
    if not isinstance(current, dict) or not isinstance(desired, dict):
        return []
    paths: list[str] = []
    for key, value in current.items():
        path = f"{prefix}.{key}" if prefix else key
        if key not in desired:
            paths.append(path)
        else:
            paths.extend(extra_paths(value, desired[key], path))
    return paths


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def classify_change(desired: dict[str, Any], current_by_name: dict[str, dict[str, Any]]) -> str:
    current = current_by_name.get(desired["displayName"])
    if current is None:
        return "CREATE"
    if normalize_graph_policy(current) == normalize_graph_policy(desired):
        return "UNCHANGED"
    return "UPDATE"


def current_policy_map(document: Any) -> dict[str, dict[str, Any]]:
    items = document.get("value", []) if isinstance(document, dict) else document
    if not isinstance(items, list):
        raise ValueError("Current-policy export must be a Graph collection or JSON array")
    return {item["displayName"]: item for item in items if isinstance(item, dict) and item.get("displayName")}
