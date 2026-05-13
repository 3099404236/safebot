import unittest

from safebot.url_utils import extract_urls, get_domain, is_domain_or_subdomain, virustotal_url_id


class UrlUtilsTest(unittest.TestCase):
    def test_extract_urls_normalizes_www_and_strips_punctuation(self):
        text = "看这个：www.example.com/a?b=1，以及 https://foo.test/path。"
        self.assertEqual(extract_urls(text), ["https://www.example.com/a?b=1", "https://foo.test/path"])

    def test_domain_helpers(self):
        self.assertEqual(get_domain("https://sub.example.com/a"), "sub.example.com")
        self.assertTrue(is_domain_or_subdomain("a.example.com", "example.com"))
        self.assertFalse(is_domain_or_subdomain("badexample.com", "example.com"))

    def test_virustotal_url_id_is_unpadded_base64(self):
        self.assertEqual(virustotal_url_id("http://x.test/"), "aHR0cDovL3gudGVzdC8")


if __name__ == "__main__":
    unittest.main()
