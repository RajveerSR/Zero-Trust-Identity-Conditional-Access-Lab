from __future__ import annotations

import copy
import unittest
from pathlib import Path

from src.ca_policy import (
    REPORT_ONLY_STATE,
    classify_change,
    example_identifier_keys,
    extra_paths,
    current_policy_map,
    graph_payload,
    load_config,
    load_policy_documents,
    normalize_graph_policy,
    read_json,
    resolve_policy,
    select_policy_documents,
    validate_collection,
    validate_policy,
)


ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = load_policy_documents(ROOT / "policies")
        cls.config, _ = load_config(
            [ROOT / "config" / "lab-identities.example.json", ROOT / "config" / "tenant.example.json"]
        )
        cls.resolved = []
        for path, document in cls.raw:
            resolved, missing = resolve_policy(document, cls.config)
            if missing:
                raise AssertionError(f"Test configuration is missing: {missing}")
            cls.resolved.append((path, resolved))

    def test_complete_policy_set_is_valid(self) -> None:
        errors = [issue for issue in validate_collection(self.raw) if issue.severity == "ERROR"]
        self.assertEqual([], errors)

    def test_selected_policy_set_has_explicit_validation_boundary(self) -> None:
        selected = select_policy_documents(self.raw, ["CA001", "CA002"])
        errors = [issue for issue in validate_collection(selected, expected_policy_ids={"CA001", "CA002"}) if issue.severity == "ERROR"]
        self.assertEqual([], errors)
        wrong_boundary = [issue.message for issue in validate_collection(selected) if issue.severity == "ERROR"]
        self.assertTrue(any("expected policy IDs" in message for message in wrong_boundary))
        with self.assertRaisesRegex(ValueError, "selected only once"):
            select_policy_documents(self.raw, ["CA001", "CA001"])

    def test_resolved_policy_set_is_valid(self) -> None:
        errors = [
            issue
            for issue in validate_collection(self.resolved, self.config["EMERGENCY_ACCESS_GROUP_ID"])
            if issue.severity == "ERROR"
        ]
        self.assertEqual([], errors)

    def test_all_definitions_are_report_only_and_exclude_emergency_group(self) -> None:
        emergency_group = self.config["EMERGENCY_ACCESS_GROUP_ID"]
        for _, document in self.resolved:
            graph = graph_payload(document)
            self.assertEqual(REPORT_ONLY_STATE, graph["state"])
            self.assertIn(emergency_group, graph["conditions"]["users"]["excludeGroups"])

    def test_device_policy_is_bounded_to_windows(self) -> None:
        by_id = {document["metadata"]["id"]: document for _, document in self.resolved}
        self.assertEqual(
            ["windows"],
            by_id["CA003"]["graph"]["conditions"]["platforms"]["includePlatforms"],
        )

    def test_repository_metadata_never_enters_graph_payload(self) -> None:
        for _, document in self.resolved:
            payload = graph_payload(document)
            self.assertNotIn("metadata", payload)
            self.assertNotIn("schemaVersion", payload)

    def test_policy_interaction_is_explicit(self) -> None:
        by_id = {doc["metadata"]["id"]: doc for _, doc in self.resolved}
        admin_group = self.config["LAB_ADMINS_GROUP_ID"]
        sensitive_app = self.config["SENSITIVE_APP_ID"]
        applicable = []
        for policy_id, document in by_id.items():
            graph = document["graph"]
            groups = graph["conditions"]["users"]["includeGroups"]
            apps = graph["conditions"]["applications"]["includeApplications"]
            if admin_group in groups and ("All" in apps or sensitive_app in apps):
                applicable.append(policy_id)
        self.assertEqual(["CA001", "CA002", "CA003"], sorted(applicable))

    def test_drift_classification(self) -> None:
        current = current_policy_map(read_json(ROOT / "tests" / "fixtures" / "current-policies.json"))
        actions = {
            document["metadata"]["id"]: classify_change(graph_payload(document), current)
            for _, document in self.resolved
        }
        self.assertEqual({"CA001": "UPDATE", "CA002": "UNCHANGED", "CA003": "CREATE"}, actions)

    def test_graph_context_annotations_do_not_trigger_policy_update(self) -> None:
        for _, document in self.resolved[:2]:
            desired = graph_payload(document)
            observed = copy.deepcopy(desired)
            observed["@odata.context"] = "https://graph.microsoft.com/v1.0/$metadata#policies"
            observed["grantControls"]["authenticationStrength@odata.context"] = "https://graph.microsoft.com/v1.0/$metadata#strength"
            strength = observed["grantControls"].get("authenticationStrength")
            if strength:
                strength["combinationConfigurations"] = []
                strength["combinationConfigurations@odata.context"] = "https://graph.microsoft.com/v1.0/$metadata#combinations"
            current = {desired["displayName"]: observed}
            self.assertEqual("UNCHANGED", classify_change(desired, current))
            observed["sessionControls"] = {"signInFrequency": {"value": 1, "type": "hours"}}
            self.assertEqual("UPDATE", classify_change(desired, current))
            self.assertIn("sessionControls", extra_paths(normalize_graph_policy(observed), normalize_graph_policy(desired)))

    def test_enabled_definition_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resolved[0][1])
        changed["graph"]["state"] = "enabled"
        messages = [issue.message for issue in validate_policy(changed) if issue.severity == "ERROR"]
        self.assertIn("repository definitions must remain report-only", messages)

    def test_all_users_scope_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resolved[0][1])
        changed["graph"]["conditions"]["users"]["includeUsers"] = ["All"]
        messages = [issue.message for issue in validate_policy(changed) if issue.severity == "ERROR"]
        self.assertIn("pilot policies must not target All users", messages)

    def test_example_identifiers_are_detected_for_deployment_guard(self) -> None:
        self.assertIn("TENANT_ID", example_identifier_keys(self.config))
        self.assertIn("LAB_USERS_GROUP_ID", example_identifier_keys(self.config))

    def test_service_empty_defaults_do_not_create_drift_but_nonempty_settings_do(self) -> None:
        desired = graph_payload(self.resolved[0][1])
        current_with_defaults = copy.deepcopy(desired)
        current_with_defaults["id"] = "30303030-3030-4030-8030-303030303030"
        current_with_defaults["sessionControls"] = None
        current_with_defaults["conditions"]["users"]["excludeUsers"] = []
        by_name = {desired["displayName"]: current_with_defaults}
        self.assertEqual("UNCHANGED", classify_change(desired, by_name))

        current_with_defaults["sessionControls"] = {"signInFrequency": {"value": 1, "type": "hours"}}
        self.assertEqual("UPDATE", classify_change(desired, by_name))
        self.assertIn(
            "sessionControls",
            extra_paths(
                normalize_graph_policy(current_with_defaults),
                normalize_graph_policy(desired),
            ),
        )

    def test_realistic_authentication_strength_metadata_is_ignored(self) -> None:
        current = current_policy_map(
            read_json(ROOT / "tests" / "fixtures" / "current-policies-realistic.json")
        )
        desired = next(
            graph_payload(document)
            for _, document in self.resolved
            if document["metadata"]["id"] == "CA002"
        )
        self.assertEqual("UNCHANGED", classify_change(desired, current))

        changed_strength = copy.deepcopy(current)
        changed_strength[desired["displayName"]]["grantControls"]["authenticationStrength"]["id"] = (
            "00000000-0000-0000-0000-000000000003"
        )
        self.assertEqual("UPDATE", classify_change(desired, changed_strength))

        changed_control = copy.deepcopy(current)
        changed_control[desired["displayName"]]["grantControls"]["builtInControls"] = ["compliantDevice"]
        self.assertEqual("UPDATE", classify_change(desired, changed_control))

    def test_duplicate_current_policy_names_are_rejected(self) -> None:
        duplicate_name = "ZT-LAB-CA001-Require-MFA-Pilot"
        with self.assertRaisesRegex(ValueError, "Ambiguous current state"):
            current_policy_map(
                [
                    {"id": "one", "displayName": duplicate_name},
                    {"id": "two", "displayName": duplicate_name},
                ]
            )

    def test_noncanonical_uuid_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resolved[0][1])
        changed["graph"]["conditions"]["users"]["includeGroups"][0] = "11111111111141118111111111111111"
        messages = [issue.message for issue in validate_policy(changed) if issue.severity == "ERROR"]
        self.assertTrue(any(message.startswith("invalid group object ID") for message in messages))


if __name__ == "__main__":
    unittest.main()
