import unittest

from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):

    def test_search_found(self):
        """Key tồn tại và role có quyền thì kết quả không được rỗng."""
        result = json_search(key1, data, role="viewer")
        self.assertNotEqual([], result)

    def test_search_not_found(self):
        """Key không tồn tại thì kết quả phải rỗng."""
        result = json_search(key2, data, role="viewer")
        self.assertEqual([], result)

    def test_is_a_list(self):
        """Kết quả trả về phải thuộc kiểu list."""
        result = json_search(key1, data, role="viewer")
        self.assertIsInstance(result, list)


    def test_sr02_admin_can_read_api_key(self):
        """SR-02: Admin được phép đọc apiKey."""
        result = json_search("apiKey", data, role="admin")
        self.assertNotEqual([], result)

    def test_sr02_operator_cannot_read_api_key(self):
        """SR-02: Operator không được phép đọc apiKey."""
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_sr02_viewer_cannot_read_api_key(self):
        """SR-02: Viewer không được phép đọc apiKey."""
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_sr03_admin_can_read_management_ip(self):
        """SR-03: Admin được phép đọc managementIpAddress."""
        result = json_search(
            "managementIpAddress",
            data,
            role="admin"
        )
        self.assertNotEqual([], result)

    def test_sr03_operator_can_read_management_ip(self):
        """SR-03: Operator được phép đọc managementIpAddress."""
        result = json_search(
            "managementIpAddress",
            data,
            role="operator"
        )
        self.assertNotEqual([], result)

    def test_sr03_viewer_cannot_read_management_ip(self):
        """SR-03: Viewer không được đọc managementIpAddress."""
        result = json_search(
            "managementIpAddress",
            data,
            role="viewer"
        )
        self.assertEqual([], result)

    def test_sr04_all_roles_can_read_issue_summary(self):
        """SR-04: Admin, operator và viewer đều đọc được issueSummary."""
        allowed_roles = ["admin", "operator", "viewer"]

        for role in allowed_roles:
            with self.subTest(role=role):
                result = json_search(
                    "issueSummary",
                    data,
                    role=role
                )
                self.assertNotEqual([], result)

    def test_sr05_unknown_role_is_denied(self):
        """SR-05: Role không tồn tại không được đọc apiKey."""
        result = json_search("apiKey", data, role="guest")
        self.assertEqual([], result)

    def test_sr05_empty_role_is_denied(self):
        """SR-05: Role rỗng không được đọc apiKey."""
        result = json_search("apiKey", data, role="")
        self.assertEqual([], result)

    def test_sr05_missing_role_is_denied(self):
        """SR-05: Thiếu role không được đọc apiKey."""
        result = json_search("apiKey", data)
        self.assertEqual([], result)

    def test_sr06_recursive_search_cannot_bypass_policy(self):
        """SR-06: Viewer không được đọc apiKey nằm sâu trong JSON."""
        nested_data = {
            "level1": [
                {
                    "level2": {
                        "apiKey": "nested-secret"
                    }
                }
            ]
        }

        viewer_result = json_search(
            "apiKey",
            nested_data,
            role="viewer"
        )

        admin_result = json_search(
            "apiKey",
            nested_data,
            role="admin"
        )

        self.assertEqual([], viewer_result)
        self.assertEqual(
            [{"apiKey": "nested-secret"}],
            admin_result
        )

    def test_sr07_denied_result_does_not_leak_secret(self):
        """SR-07: Kết quả bị từ chối không được chứa apiKey thật."""
        secret = "SNMP-COMMUNITY-STRING-7f3a9c"

        result = json_search(
            "apiKey",
            data,
            role="viewer"
        )

        self.assertEqual([], result)
        self.assertNotIn(secret, repr(result))


if __name__ == "__main__":
    unittest.main()