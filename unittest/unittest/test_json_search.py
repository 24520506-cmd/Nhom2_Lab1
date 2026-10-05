import unittest

from recursive_json_search import *
from test_data import *


class json_search_test(unittest.TestCase):

    def test_search_found(self):
        """Key tồn tại thì kết quả không được rỗng."""
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        """Key không tồn tại thì kết quả phải rỗng."""
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        """Kết quả trả về phải thuộc kiểu list."""
        self.assertIsInstance(json_search(key1, data), list)


if __name__ == "__main__":
    unittest.main()
