"""
Unit tests for StackScope's signature-matching and risk-flagging logic.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import stackscope as ss  # noqa: E402


class TestServerDetection(unittest.TestCase):

    def test_apache_with_version(self):
        found = ss.detect_server({"Server": "Apache/2.4.29 (Ubuntu)"})
        self.assertEqual(found[0].name, "Apache")
        self.assertEqual(found[0].version, "2.4.29")
        self.assertEqual(found[0].confidence, "HIGH")

    def test_nginx_with_version(self):
        found = ss.detect_server({"Server": "nginx/1.25.3"})
        self.assertEqual(found[0].name, "Nginx")
        self.assertEqual(found[0].version, "1.25.3")

    def test_unknown_server_still_reported(self):
        found = ss.detect_server({"Server": "MysteryServer/9.9"})
        self.assertEqual(found[0].confidence, "MEDIUM")

    def test_no_server_header(self):
        self.assertEqual(ss.detect_server({}), [])


class TestFrameworkDetection(unittest.TestCase):

    def test_php_version_extracted_from_header(self):
        found = ss.detect_frameworks({"X-Powered-By": "PHP/7.2.24"}, "")
        php = next(f for f in found if f.name == "PHP")
        self.assertEqual(php.version, "7.2.24")
        self.assertEqual(php.confidence, "HIGH")

    def test_laravel_detected_from_cookie_header(self):
        found = ss.detect_frameworks({"Set-Cookie": "laravel_session=abc123"}, "")
        self.assertTrue(any(f.name == "Laravel" for f in found))

    def test_nextjs_detected_from_html(self):
        found = ss.detect_frameworks({}, '<script src="/_next/static/chunks/main.js">')
        self.assertTrue(any(f.name == "Next.js" for f in found))


class TestCMSDetection(unittest.TestCase):

    def test_wordpress_meta_generator_high_confidence(self):
        html = '<meta name="generator" content="WordPress 6.2" />'
        found = ss.detect_cms({}, html)
        wp = next(f for f in found if f.name == "WordPress")
        self.assertEqual(wp.confidence, "HIGH")
        self.assertEqual(wp.version, "6.2")

    def test_shopify_detected_via_header(self):
        found = ss.detect_cms({"X-ShopId": "12345"}, "")
        self.assertTrue(any(f.name == "Shopify" for f in found))


class TestVersionRiskChecks(unittest.TestCase):

    def test_outdated_php_flagged(self):
        techs = [ss.Technology("Framework", "PHP", "7.2.24", "HIGH", "")]
        disclosures, outdated = ss.check_version_risks(techs)
        self.assertIn("PHP 7.2.24", disclosures)
        self.assertTrue(any("PHP 7.2.24" in o for o in outdated))

    def test_current_php_not_flagged_outdated(self):
        techs = [ss.Technology("Framework", "PHP", "8.3.0", "HIGH", "")]
        _, outdated = ss.check_version_risks(techs)
        self.assertEqual(outdated, [])

    def test_no_version_no_disclosure(self):
        techs = [ss.Technology("CMS", "Shopify", None, "HIGH", "")]
        disclosures, outdated = ss.check_version_risks(techs)
        self.assertEqual(disclosures, [])
        self.assertEqual(outdated, [])


class TestDedupe(unittest.TestCase):

    def test_high_confidence_wins_over_medium(self):
        techs = [
            ss.Technology("CMS", "WordPress", None, "MEDIUM", "html"),
            ss.Technology("CMS", "WordPress", "6.2", "HIGH", "meta"),
        ]
        result = ss.dedupe(techs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].confidence, "HIGH")
        self.assertEqual(result[0].version, "6.2")

    def test_different_categories_not_merged(self):
        techs = [
            ss.Technology("CMS", "WordPress", None, "HIGH", "a"),
            ss.Technology("Framework", "WordPress", None, "HIGH", "b"),
        ]
        result = ss.dedupe(techs)
        self.assertEqual(len(result), 2)


class TestVersionTupleParsing(unittest.TestCase):

    def test_parses_major_minor(self):
        self.assertEqual(ss._parse_version_tuple("7.2.24"), (7, 2))

    def test_invalid_version_returns_none(self):
        self.assertIsNone(ss._parse_version_tuple("not-a-version"))


if __name__ == "__main__":
    unittest.main()
