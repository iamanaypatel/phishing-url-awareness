"""Phishing URL Awareness Checker.

A beginner-friendly, educational cybersecurity tool that analyzes URL text for
common phishing indicators without making any network requests or visiting
the target web address.

Designed for the EWB Cybersecurity Mini Project.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

__version__ = "1.2.0"
__author__ = "Anay Patel"

# Standard Informational Messages
INFO_NO_URL = "No URL entered."
INFO_NO_HOSTNAME = "Could not identify a hostname."
INFO_INVALID_FORMAT = "This text is not a valid URL format."
INFO_NO_WARNINGS = "No listed warning signs found. This does NOT prove safety."

INFO_MESSAGES = (
    INFO_NO_URL,
    INFO_NO_HOSTNAME,
    INFO_INVALID_FORMAT,
    INFO_NO_WARNINGS,
)

# Rule Identifiers and Detailed Educational Explanations
RULE_DEFINITIONS: dict[str, dict[str, str]] = {
    "AT_SYMBOL": {
        "title": "Contains an @ symbol; inspect carefully.",
        "explanation": (
            "In URL standard syntax (RFC 3986), characters before '@' represent "
            "user authentication info, not the destination host. Web browsers "
            "ignore everything before '@' for server routing and navigate to the "
            "host AFTER the '@'. Phishers exploit this to mimic trusted brand names "
            "(e.g., http://trusted-bank.com@evil-site.com)."
        ),
    },
    "URL_LENGTH": {
        "title": "Unusually long URL (over 100 characters).",
        "explanation": (
            "Attackers frequently construct excessively long URLs to conceal "
            "suspicious subdomains, bury malicious query parameters, or ensure "
            "the actual destination domain is truncated and pushed off-screen "
            "in mobile address bars and email interfaces."
        ),
    },
    "IP_ADDRESS": {
        "title": "Uses an IP address instead of a familiar domain.",
        "explanation": (
            "Legitimate websites almost always use registered domain names (e.g., "
            "example.com) with verifiable TLS certificates. Bare IP addresses bypass "
            "standard domain-name reputation filters and often point directly to "
            "compromised or disposable hosting servers."
        ),
    },
    "MANY_SEGMENTS": {
        "title": "Contains many hostname segments/subdomains.",
        "explanation": (
            "Five or more dot-separated segments (e.g., login.portal.account.brand.attacker.com) "
            "are frequently used in phishing attacks to display a recognized brand "
            "name on the left while routing the victim to an entirely different, "
            "attacker-controlled registered domain on the right."
        ),
    },
    "PUNYCODE": {
        "title": "Contains a punycode-style hostname.",
        "explanation": (
            "Punycode (prefixed with 'xn--') encodes non-ASCII Internationalized "
            "Domain Names (IDNs) into ASCII format. In 'homograph attacks', attackers "
            "substitute lookalike characters from other alphabets (such as Cyrillic 'а' "
            "for Latin 'a') to create fake domains visually indistinguishable from legitimate ones."
        ),
    },
    "HTTP_SCHEME": {
        "title": "Uses HTTP. HTTPS alone does not prove trust.",
        "explanation": (
            "Plain HTTP transmits passwords and sensitive data in unencrypted cleartext, "
            "vulnerable to network interception and tampering. Important: Even if HTTPS "
            "is present, encryption alone does not guarantee a site is safe—modern phishing "
            "websites routinely obtain legitimate free HTTPS certificates."
        ),
    },
}


def is_ipv4_address(host: str) -> bool:
    """Return True if host is a strictly valid IPv4 dotted-decimal address.

    Uses Python's standard ipaddress module to ensure accurate validation
    (0-255 per octet) rather than a loose regular expression.
    """
    if not host:
        return False
    try:
        ipaddress.IPv4Address(host)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def parse_url_safely(raw_url: str) -> tuple[Any, str, str, int | None, str | None]:
    """Parse a raw URL string safely without throwing unhandled exceptions.

    Returns:
        tuple of (parsed_result, candidate_url, host_lowercase, port, error_message)
    """
    url = raw_url.strip()
    if not url:
        return None, "", "", None, INFO_NO_URL

    # Normalize URLs without a scheme so urlparse extracts the netloc/hostname
    # correctly, without altering the explicit scheme value.
    if "://" in url:
        candidate = url
    elif url.startswith("//"):
        candidate = url
    else:
        candidate = "//" + url

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except (ValueError, Exception):
        return None, "", "", None, INFO_INVALID_FORMAT

    # Check for empty hostname or invalid whitespace in hostname
    if not host or any(char.isspace() for char in host):
        if host and any(char.isspace() for char in host):
            return None, "", "", None, INFO_INVALID_FORMAT
        return None, "", "", None, INFO_NO_HOSTNAME

    return parsed, candidate, host, port, None


def inspect_url(raw_url: str) -> list[str]:
    """Check URL text for selected warning signs without opening the URL.

    Maintains full compatibility with the workbook detection rules and test
    expectations. Returns a list of warning message strings if detected,
    or a single-element list with an informational status message.
    """
    url = raw_url.strip()
    if not url:
        return [INFO_NO_URL]

    parsed, _, host, _, err = parse_url_safely(url)
    if err:
        return [err]

    findings: list[str] = []

    # Rule 1: @ symbol detection
    if "@" in url:
        findings.append(RULE_DEFINITIONS["AT_SYMBOL"]["title"])

    # Rule 2: Excessive URL length (> 100 characters)
    if len(url) > 100:
        findings.append(RULE_DEFINITIONS["URL_LENGTH"]["title"])

    # Rule 3: IPv4 address used as hostname
    if is_ipv4_address(host):
        findings.append(RULE_DEFINITIONS["IP_ADDRESS"]["title"])

    # Rule 4: Five or more hostname segments (dots/subdomains)
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append(RULE_DEFINITIONS["MANY_SEGMENTS"]["title"])

    # Rule 5: Punycode marker (xn--) in hostname
    if "xn--" in host:
        findings.append(RULE_DEFINITIONS["PUNYCODE"]["title"])

    # Rule 6: HTTP protocol instead of HTTPS
    if parsed.scheme.lower() == "http":
        findings.append(RULE_DEFINITIONS["HTTP_SCHEME"]["title"])

    # Default message when no listed warning signs were found
    if not findings:
        findings.append(INFO_NO_WARNINGS)

    return findings


def has_warnings(findings: list[str]) -> bool:
    """Return True when at least one actual warning sign was found."""
    if not findings:
        return False
    return not any(
        item.startswith(prefix) for item in findings for prefix in INFO_MESSAGES
    )


def get_risk_indicator(warning_count: int) -> dict[str, str]:
    """Calculate an educational risk heuristic based on the number of warning signs.

    Note: Clearly labeled as an educational heuristic, not a commercial
    threat score or a guarantee of safety.
    """
    if warning_count == 0:
        return {
            "level": "LOW",
            "summary": "0 of 6 warning flags triggered.",
            "note": (
                "No listed rule flags triggered. However, absence of flags does "
                "NOT prove a link is safe. Attackers frequently register fresh domains "
                "and obtain valid HTTPS certificates."
            ),
        }
    if warning_count in (1, 2):
        return {
            "level": "MODERATE",
            "summary": f"{warning_count} of 6 warning flag(s) triggered.",
            "note": (
                "One or more common phishing indicators were detected. Exercise "
                "caution and independently verify the source before interacting."
            ),
        }
    return {
        "level": "ELEVATED",
        "summary": f"{warning_count} of 6 warning flags triggered.",
        "note": (
            "Multiple suspicious indicators detected. High likelihood of deceptive "
            "formatting. Do not open or provide credentials."
        ),
    }


def analyze_url(raw_url: str) -> dict[str, Any]:
    """Perform comprehensive structural and rule-based analysis on a URL.

    Separates detection logic from presentation, providing rich metadata,
    explanations, warning counts, and educational heuristics.
    """
    url = raw_url.strip()
    if not url:
        return {
            "raw_url": raw_url,
            "status": "error",
            "info_message": INFO_NO_URL,
            "hostname": "",
            "scheme": "",
            "port": None,
            "warnings": [],
            "warning_count": 0,
            "has_warnings": False,
            "risk_indicator": get_risk_indicator(0),
        }

    parsed, _, host, port, err = parse_url_safely(url)
    if err:
        return {
            "raw_url": raw_url,
            "status": "error",
            "info_message": err,
            "hostname": "",
            "scheme": "",
            "port": None,
            "warnings": [],
            "warning_count": 0,
            "has_warnings": False,
            "risk_indicator": get_risk_indicator(0),
        }

    warnings: list[dict[str, str]] = []

    # Rule 1: @ symbol
    if "@" in url:
        warnings.append({
            "code": "AT_SYMBOL",
            "title": RULE_DEFINITIONS["AT_SYMBOL"]["title"],
            "explanation": RULE_DEFINITIONS["AT_SYMBOL"]["explanation"],
        })

    # Rule 2: URL length > 100
    if len(url) > 100:
        warnings.append({
            "code": "URL_LENGTH",
            "title": RULE_DEFINITIONS["URL_LENGTH"]["title"],
            "explanation": RULE_DEFINITIONS["URL_LENGTH"]["explanation"],
        })

    # Rule 3: IPv4 address as hostname
    if is_ipv4_address(host):
        warnings.append({
            "code": "IP_ADDRESS",
            "title": RULE_DEFINITIONS["IP_ADDRESS"]["title"],
            "explanation": RULE_DEFINITIONS["IP_ADDRESS"]["explanation"],
        })

    # Rule 4: 5+ hostname segments
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        warnings.append({
            "code": "MANY_SEGMENTS",
            "title": RULE_DEFINITIONS["MANY_SEGMENTS"]["title"],
            "explanation": RULE_DEFINITIONS["MANY_SEGMENTS"]["explanation"],
        })

    # Rule 5: Punycode hostname
    if "xn--" in host:
        warnings.append({
            "code": "PUNYCODE",
            "title": RULE_DEFINITIONS["PUNYCODE"]["title"],
            "explanation": RULE_DEFINITIONS["PUNYCODE"]["explanation"],
        })

    # Rule 6: HTTP scheme
    if parsed.scheme.lower() == "http":
        warnings.append({
            "code": "HTTP_SCHEME",
            "title": RULE_DEFINITIONS["HTTP_SCHEME"]["title"],
            "explanation": RULE_DEFINITIONS["HTTP_SCHEME"]["explanation"],
        })

    warning_count = len(warnings)
    has_warn = warning_count > 0

    return {
        "raw_url": raw_url,
        "status": "ok",
        "info_message": None if has_warn else INFO_NO_WARNINGS,
        "hostname": host,
        "scheme": parsed.scheme.lower() if parsed.scheme else "(none)",
        "port": port,
        "warnings": warnings,
        "warning_count": warning_count,
        "has_warnings": has_warn,
        "risk_indicator": get_risk_indicator(warning_count),
    }


def format_analysis_report(analysis: dict[str, Any]) -> str:
    """Format an analysis dictionary into a clean, professional terminal report."""
    lines: list[str] = []
    lines.append("-" * 70)
    lines.append(f"URL Under Inspection: {analysis['raw_url'].strip() or '(empty)'}")

    if analysis["status"] == "error":
        lines.append("-" * 70)
        lines.append(f"[!] Informational Notice: {analysis['info_message']}")
        if analysis["info_message"] == INFO_INVALID_FORMAT:
            lines.append("    Tip: Verify that the URL adheres to standard web formatting.")
        elif analysis["info_message"] == INFO_NO_HOSTNAME:
            lines.append("    Tip: Ensure the URL contains a valid domain name or IP address.")
        lines.append("-" * 70)
        return "\n".join(lines)

    lines.append(f"Parsed Hostname     : {analysis['hostname']}")
    scheme_display = analysis["scheme"] if analysis["scheme"] != "(none)" else "(no scheme specified)"
    lines.append(f"Detected Scheme     : {scheme_display}")
    if analysis["port"]:
        lines.append(f"Explicit Port       : {analysis['port']}")
    lines.append("-" * 70)

    if analysis["has_warnings"]:
        count = analysis["warning_count"]
        lines.append(f"[!] REVIEW CAREFULLY: {count} warning sign(s) detected.\n")
        lines.append("Detected Warning Signs:")
        for idx, warning in enumerate(analysis["warnings"], start=1):
            lines.append(f"  {idx}. {warning['title']}")
            # Wrap explanation cleanly with indentation
            words = warning["explanation"].split()
            current_line = "     Why it matters: "
            for word in words:
                if len(current_line) + len(word) + 1 > 68:
                    lines.append(current_line)
                    current_line = "     " + word
                else:
                    current_line += word if current_line.endswith(": ") or current_line == "     " else " " + word
            if current_line.strip():
                lines.append(current_line)
            lines.append("")

        risk = analysis["risk_indicator"]
        lines.append(f"Educational Risk Indicator: {risk['level']} ({risk['summary']})")
        lines.append(f"* {risk['note']}")
    else:
        lines.append("[i] Informational Result:")
        lines.append(f"  - {analysis['info_message']}\n")
        risk = analysis["risk_indicator"]
        lines.append(f"Educational Risk Indicator: {risk['level']} ({risk['summary']})")
        lines.append(f"* {risk['note']}")

    lines.append("-" * 70)
    lines.append("Defensive Guidance: Never enter passwords or OTPs from unexpected links.")
    lines.append("-" * 70)
    return "\n".join(lines)


def print_banner() -> None:
    """Print the educational program header and disclaimer."""
    print("=" * 70)
    print(f"     EWB Phishing URL Awareness Checker (v{__version__})")
    print("     Defensive Cybersecurity Educational Tool")
    print("=" * 70)
    print("[Educational Disclaimer]")
    print("This program performs static lexical analysis on URL text only.")
    print("It NEVER connects to, downloads from, or visits submitted URLs.")
    print("Results are educational clues; no rule-based heuristic can prove")
    print("that a URL is definitely safe or malicious.")
    print("=" * 70)
    print("Commands: Enter a URL to inspect, or type 'q', 'quit', or 'exit' to quit.")


def main() -> None:
    """Run the interactive multi-URL inspection CLI loop."""
    print_banner()

    while True:
        try:
            raw_url = input("\nEnter a sample URL (or type q to quit): ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting session. Stay alert online!")
            break

        cleaned = raw_url.strip()
        if cleaned.lower() in ("q", "quit", "exit"):
            print("Exiting Phishing URL Awareness Checker. Stay alert online!")
            break

        analysis = analyze_url(raw_url)
        print("\n" + format_analysis_report(analysis))


if __name__ == "__main__":
    main()
