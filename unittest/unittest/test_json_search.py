"""Functional and specification-derived security tests for JSON search."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):
    def setUp(self):
        self.summary = data["enrichmentInfo"]["issueDetails"]["issue"][0]["issueSummary"]
        self.device = data["enrichmentInfo"]["connectedDevice"][0]["deviceDetails"]

    def test_search_found(self):
        """Return the matching nested dictionary for an allowed role."""
        self.assertEqual(json_search(key1, data, "viewer"), [{key1: self.summary}])

    def test_search_not_found(self):
        """Return an empty list for absent keys, including an allowed key."""
        self.assertEqual(json_search(key2, data, "admin"), [])
        self.assertEqual(json_search("issueSummary", {"items": []}, "viewer"), [])

    def test_is_a_list(self):
        """Return a list when a permitted match exists."""
        self.assertIsInstance(json_search(key1, data, "viewer"), list)

    def test_api_key_permissions(self):
        """SR-01/02/05: only admin can read apiKey."""
        for role, allowed in (("admin", True), ("operator", False), ("viewer", False)):
            with self.subTest(role=role):
                expected = [{"apiKey": self.device["apiKey"]}] if allowed else []
                self.assertEqual(json_search("apiKey", data, role), expected)

    def test_management_ip_permissions(self):
        """SR-01/03/05: admin and operator can read the management IP."""
        for role, allowed in (("admin", True), ("operator", True), ("viewer", False)):
            with self.subTest(role=role):
                expected = [{"managementIpAddress": self.device["managementIpAddress"]}] if allowed else []
                self.assertEqual(json_search("managementIpAddress", data, role), expected)

    def test_issue_summary_permissions(self):
        """SR-01/04: all three roles receive the expected summary."""
        for role in ("admin", "operator", "viewer"):
            with self.subTest(role=role):
                self.assertEqual(json_search(key1, data, role), [{key1: self.summary}])

    def test_missing_role_denied(self):
        """SR-05: omitting the role denies every protected field."""
        for key in ("apiKey", "managementIpAddress", "issueSummary"):
            with self.subTest(key=key):
                self.assertEqual(json_search(key, data), [])

    def test_invalid_roles_denied(self):
        """SR-05: empty, unknown and explicit None roles receive exactly []."""
        for role in ("", "guest", None):
            for key in ("apiKey", "managementIpAddress", "issueSummary"):
                with self.subTest(role=role, key=key):
                    self.assertEqual(json_search(key, data, role), [])

    def test_nested_permissions_and_aggregation(self):
        """SR-06: collect every allowed match and deny all nested secret matches."""
        secret = self.device["apiKey"]
        nested = [
            {"apiKey": secret},
            {"items": [{"apiKey": secret}, [{"deep": {"apiKey": secret}}]]},
        ]
        self.assertEqual(json_search("apiKey", nested, "admin"), [{"apiKey": secret}] * 3)
        for role in ("operator", "viewer"):
            with self.subTest(role=role):
                self.assertEqual(json_search("apiKey", nested, role), [])

    def test_parent_containers_do_not_leak(self):
        """SR-06: an allowed parent key cannot expose a denied descendant."""
        for value in ({"apiKey": self.device["apiKey"]}, [{"apiKey": self.device["apiKey"]}]):
            nested = {"issueSummary": value}
            for role in ("operator", "viewer"):
                with self.subTest(role=role, container=type(value).__name__):
                    self.assertEqual(json_search("issueSummary", nested, role), [])
            self.assertEqual(json_search("issueSummary", nested, "admin"), [nested])
        nested = {"issueSummary": {"issueSummary": "allowed descendant"}}
        self.assertEqual(json_search("issueSummary", nested, "viewer"),
                         [nested, {"issueSummary": "allowed descendant"}])

    def test_keys_outside_policy_denied(self):
        """Approved default-deny rule and SR-06: unknown parents expose nothing."""
        for role in ("admin", "operator", "viewer"):
            with self.subTest(role=role):
                self.assertEqual(json_search("deviceDetails", data, role), [])
                self.assertEqual(json_search("hostname", data, role), [])
                self.assertEqual(json_search("issueSummary", {"issueSummary": {"unknown": "value"}}, role), [])

    def test_denial_does_not_disclose_secret(self):
        """SR-05/07: denial is silent, raises no error, and exposes no secret."""
        for role in ("operator", "viewer", "guest", "", None):
            with self.subTest(role=role):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr), self.assertNoLogs(level="DEBUG"):
                    result = json_search("apiKey", data, role)
                self.assertEqual(result, [])
                self.assertNotIn(self.device["apiKey"], repr(result))
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
