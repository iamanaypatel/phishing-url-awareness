"""Unit tests for Phishing URL Awareness Checker.

Comprehensive automated test suite covering:
- All 5 workbook sample test cases
- All 6 phishing detection rules
- Empty and whitespace input handling
- Missing URL scheme normalization
- Malformed URL and invalid hostname handling
- Complex URLs (ports, paths, query strings, fragments)
- Educational risk heuristics and report formatting
- Multi-URL interactive loop exit behavior

Uses only Python's standard library (unittest) with zero third-party dependencies.
All test samples use reserved example domains (RFC 2606) and documentation IP blocks (RFC 5737).
"""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

import phishing_checker
from phishing_checker import (
    INFO_INVALID_FORMAT,
    INFO_NO_HOSTNAME,
    INFO_NO_URL,
    INFO_NO_WARNINGS,
    analyze_url,
    format_analysis_report,
    get_risk_indicator,
    has_warnings,
    inspect_url,
    is_ipv4_address,
    parse_url_safely,
)


class TestWorkbookSampleCases(unittest.TestCase):
    """Verify exact expected behavior for the five required workbook sample URLs."""

    def test_sample_1_legitimate_url(self):
        """Case 1: Standard HTTPS URL should trigger zero warning signs."""
        url = "https://www.example.com/login"
        findings = inspect_url(url)
        self.assertEqual(findings, [INFO_NO_WARNINGS])
        self.assertFalse(has_warnings(findings))

    def test_sample_2_ip_address_and_http(self):
        """Case 2: Bare IPv4 address over HTTP should flag IP and HTTP."""
        url = "http://192.0.2.10/account"
        findings = inspect_url(url)
        self.assertTrue(has_warnings(findings))
        self.assertEqual(len(findings), 2)
        self.assertIn("Uses an IP address instead of a familiar domain.", findings)
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", findings)

    def test_sample_3_at_symbol_and_http(self):
        """Case 3: URL containing '@' symbol over HTTP should flag @ and HTTP."""
        url = "http://example.com@sample.invalid/login"
        findings = inspect_url(url)
        self.assertTrue(has_warnings(findings))
        self.assertEqual(len(findings), 2)
        self.assertIn("Contains an @ symbol; inspect carefully.", findings)
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", findings)

    def test_sample_4_many_hostname_segments(self):
        """Case 4: Hostname with 5 or more segments should flag subdomains."""
        url = "https://a.b.c.d.e.example.invalid/path"
        findings = inspect_url(url)
        self.assertTrue(has_warnings(findings))
        self.assertEqual(len(findings), 1)
        self.assertIn("Contains many hostname segments/subdomains.", findings)

    def test_sample_5_punycode_hostname(self):
        """Case 5: Hostname containing 'xn--' punycode prefix should be flagged."""
        url = "https://xn--example.invalid/"
        findings = inspect_url(url)
        self.assertTrue(has_warnings(findings))
        self.assertEqual(len(findings), 1)
        self.assertIn("Contains a punycode-style hostname.", findings)


class TestDetectionRules(unittest.TestCase):
    """Verify each of the six detection rules individually."""

    def test_rule_1_at_symbol_detection(self):
        """Rule 1: '@' symbol in URL must be detected."""
        url_with_at = "https://trusted-service.example.net@malicious.example.org/login"
        findings = inspect_url(url_with_at)
        self.assertIn("Contains an @ symbol; inspect carefully.", findings)

        url_without_at = "https://trusted-service.example.net/login"
        self.assertNotIn("Contains an @ symbol; inspect carefully.", inspect_url(url_without_at))

    def test_rule_2_excessive_url_length(self):
        """Rule 2: URLs with length strictly greater than 100 characters must be flagged."""
        # 100 characters exact -> should NOT trigger length warning
        url_100_chars = "https://example.com/" + ("a" * 80)
        self.assertEqual(len(url_100_chars), 100)
        findings_100 = inspect_url(url_100_chars)
        self.assertNotIn("Unusually long URL (over 100 characters).", findings_100)

        # 101 characters -> MUST trigger length warning
        url_101_chars = "https://example.com/" + ("a" * 81)
        self.assertEqual(len(url_101_chars), 101)
        findings_101 = inspect_url(url_101_chars)
        self.assertIn("Unusually long URL (over 100 characters).", findings_101)

    def test_rule_3_ipv4_address_validation(self):
        """Rule 3: Accurate IPv4 address detection using standard ipaddress library."""
        # Valid documentation IPs (RFC 5737)
        self.assertTrue(is_ipv4_address("192.0.2.1"))
        self.assertTrue(is_ipv4_address("198.51.100.42"))
        self.assertTrue(is_ipv4_address("203.0.113.254"))

        findings = inspect_url("https://198.51.100.1/secure")
        self.assertIn("Uses an IP address instead of a familiar domain.", findings)

        # Invalid IPv4 numbers (out-of-bounds octets) must NOT be flagged as IP
        self.assertFalse(is_ipv4_address("999.999.999.999"))
        self.assertFalse(is_ipv4_address("256.0.0.1"))
        self.assertFalse(is_ipv4_address("example.com"))

        findings_invalid_ip = inspect_url("https://999.999.999.999/path")
        self.assertNotIn("Uses an IP address instead of a familiar domain.", findings_invalid_ip)

    def test_rule_4_hostname_segments(self):
        """Rule 4: Five or more dot-separated segments must be flagged."""
        # 4 segments: 'one.two.example.com' -> should NOT flag
        url_4_segments = "https://one.two.example.com/test"
        self.assertNotIn("Contains many hostname segments/subdomains.", inspect_url(url_4_segments))

        # 5 segments: 'one.two.three.example.com' -> MUST flag
        url_5_segments = "https://one.two.three.example.com/test"
        self.assertIn("Contains many hostname segments/subdomains.", inspect_url(url_5_segments))

        # 6 segments: 'a.b.c.d.example.com' -> MUST flag
        url_6_segments = "https://a.b.c.d.example.com/test"
        self.assertIn("Contains many hostname segments/subdomains.", inspect_url(url_6_segments))

    def test_rule_5_punycode_marker(self):
        """Rule 5: Hostname containing 'xn--' must trigger Punycode warning."""
        url_punycode = "https://xn--e1afmkfd.example.invalid/portal"
        findings = inspect_url(url_punycode)
        self.assertIn("Contains a punycode-style hostname.", findings)

        url_regular = "https://regular-domain.example.com/portal"
        self.assertNotIn("Contains a punycode-style hostname.", inspect_url(url_regular))

    def test_rule_6_http_scheme(self):
        """Rule 6: Explicit HTTP protocol must trigger warning; HTTPS must not."""
        url_http = "http://example.com/login"
        self.assertIn("Uses HTTP. HTTPS alone does not prove trust.", inspect_url(url_http))

        url_https = "https://example.com/login"
        self.assertNotIn("Uses HTTP. HTTPS alone does not prove trust.", inspect_url(url_https))


class TestInputHandlingAndEdgeCases(unittest.TestCase):
    """Verify robust parsing, normalization, whitespace handling, and error safety."""

    def test_empty_input(self):
        """Empty string must return INFO_NO_URL without crashing."""
        findings = inspect_url("")
        self.assertEqual(findings, [INFO_NO_URL])
        self.assertFalse(has_warnings(findings))

    def test_whitespace_input(self):
        """Whitespace-only input (spaces, tabs, newlines) must return INFO_NO_URL."""
        findings = inspect_url("   \t\n  ")
        self.assertEqual(findings, [INFO_NO_URL])
        self.assertFalse(has_warnings(findings))

    def test_missing_scheme_handling(self):
        """URLs provided without scheme (e.g. 'example.com/path') parse correctly.

        They must not be falsely flagged as HTTP, but still evaluate other rules.
        """
        # Clean domain without scheme
        findings = inspect_url("example.com/login")
        self.assertEqual(findings, [INFO_NO_WARNINGS])
        self.assertFalse(has_warnings(findings))

        # IP address without scheme
        findings_ip = inspect_url("192.0.2.1/login")
        self.assertIn("Uses an IP address instead of a familiar domain.", findings_ip)
        self.assertNotIn("Uses HTTP. HTTPS alone does not prove trust.", findings_ip)

    def test_malformed_url_brackets(self):
        """Malformed URL strings (such as invalid IPv6 brackets) must not crash."""
        findings = inspect_url("http://[invalid-ipv6-bracket]/")
        self.assertEqual(findings, [INFO_INVALID_FORMAT])
        self.assertFalse(has_warnings(findings))

    def test_missing_hostname(self):
        """URLs lacking a host (e.g. 'http://') must be caught safely."""
        findings = inspect_url("http://")
        self.assertEqual(findings, [INFO_NO_HOSTNAME])
        self.assertFalse(has_warnings(findings))

        findings_https = inspect_url("https://")
        self.assertEqual(findings_https, [INFO_NO_HOSTNAME])
        self.assertFalse(has_warnings(findings_https))

    def test_whitespace_inside_hostname(self):
        """Text with spaces in the hostname component must be flagged as invalid format."""
        findings = inspect_url("this is not a url")
        self.assertEqual(findings, [INFO_INVALID_FORMAT])
        self.assertFalse(has_warnings(findings))

    def test_url_with_port_path_query_fragment(self):
        """URLs containing ports, paths, query strings, and fragments parse cleanly."""
        url = "https://example.com:8443/api/v1/resource?user=alice&sort=asc#results"
        parsed, _, host, port, err = parse_url_safely(url)
        self.assertIsNone(err)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)
        self.assertEqual(inspect_url(url), [INFO_NO_WARNINGS])

    def test_has_warnings_edge_cases(self):
        """Verify has_warnings behaves correctly with empty list, info strings, and warnings."""
        self.assertFalse(has_warnings([]))
        self.assertFalse(has_warnings([INFO_NO_URL]))
        self.assertFalse(has_warnings([INFO_NO_HOSTNAME]))
        self.assertFalse(has_warnings([INFO_INVALID_FORMAT]))
        self.assertFalse(has_warnings([INFO_NO_WARNINGS]))
        self.assertTrue(has_warnings(["Contains an @ symbol; inspect carefully."]))


class TestAnalysisAndReporting(unittest.TestCase):
    """Verify structured analysis, educational heuristics, and report formatting."""

    def test_analyze_url_structure(self):
        """analyze_url() should produce a complete metadata dictionary."""
        analysis = analyze_url("http://192.0.2.10/account")
        self.assertEqual(analysis["status"], "ok")
        self.assertEqual(analysis["hostname"], "192.0.2.10")
        self.assertEqual(analysis["scheme"], "http")
        self.assertTrue(analysis["has_warnings"])
        self.assertEqual(analysis["warning_count"], 2)
        self.assertEqual(analysis["risk_indicator"]["level"], "MODERATE")
        self.assertEqual(len(analysis["warnings"]), 2)

    def test_educational_risk_heuristic_levels(self):
        """Verify risk heuristic levels based on flag count."""
        low = get_risk_indicator(0)
        self.assertEqual(low["level"], "LOW")

        mod1 = get_risk_indicator(1)
        self.assertEqual(mod1["level"], "MODERATE")

        mod2 = get_risk_indicator(2)
        self.assertEqual(mod2["level"], "MODERATE")

        elev = get_risk_indicator(3)
        self.assertEqual(elev["level"], "ELEVATED")

    def test_format_analysis_report_output(self):
        """format_analysis_report() produces clear text with review warnings."""
        analysis = analyze_url("http://192.0.2.10/account")
        report = format_analysis_report(analysis)
        self.assertIn("REVIEW CAREFULLY: 2 warning sign(s) detected.", report)
        self.assertIn("Why it matters:", report)
        self.assertIn("Educational Risk Indicator: MODERATE", report)
        self.assertIn("Defensive Guidance:", report)

    def test_format_analysis_report_informational(self):
        """Report for safe URL clearly shows informational status without panic banner."""
        analysis = analyze_url("https://www.example.com/login")
        report = format_analysis_report(analysis)
        self.assertIn("[i] Informational Result:", report)
        self.assertIn("No listed warning signs found. This does NOT prove safety.", report)
        self.assertNotIn("REVIEW CAREFULLY", report)


class TestInteractiveLoopBehavior(unittest.TestCase):
    """Verify CLI exit triggers and simulated interaction without hanging."""

    @patch("builtins.input", side_effect=["q"])
    def test_interactive_quit_q(self, _mock_input):
        """User typing 'q' exits the main loop immediately."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            phishing_checker.main()
            output = mock_stdout.getvalue()
            self.assertIn("Exiting Phishing URL Awareness Checker", output)

    @patch("builtins.input", side_effect=["exit"])
    def test_interactive_quit_exit(self, _mock_input):
        """User typing 'exit' exits the main loop cleanly."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            phishing_checker.main()
            output = mock_stdout.getvalue()
            self.assertIn("Exiting Phishing URL Awareness Checker", output)

    @patch("builtins.input", side_effect=["https://www.example.com/login", "quit"])
    def test_interactive_multi_url_loop(self, _mock_input):
        """Loop processes a URL and subsequently terminates when 'quit' is entered."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            phishing_checker.main()
            output = mock_stdout.getvalue()
            self.assertIn("https://www.example.com/login", output)
            self.assertIn("No listed warning signs found", output)
            self.assertIn("Exiting Phishing URL Awareness Checker", output)


if __name__ == "__main__":
    unittest.main()
