import tempfile
import unittest
from pathlib import Path

from safebot.whitelist import Whitelist


class WhitelistTest(unittest.TestCase):
    def test_add_remove_and_subdomain_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "whitelist.json"
            whitelist = Whitelist(path)
            whitelist.add("https://example.com/path")

            self.assertTrue(whitelist.contains_url("https://sub.example.com/a"))
            self.assertFalse(whitelist.contains_url("https://example.org/a"))

            whitelist.remove("example.com")
            self.assertFalse(whitelist.contains_url("https://example.com/a"))


if __name__ == "__main__":
    unittest.main()
