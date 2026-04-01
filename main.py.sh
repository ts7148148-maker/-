#!/usr/bin/env python3
"""
Enhanced Phishing Detection Tool
--------------------------------
A production-ready module for detecting potential phishing URLs.
Features:
- Analyzes URLs for common phishing indicators
- Checks for homograph attacks using Unicode normalization
- Validates SSL certificates (optional)
- Supports batch processing from file
- Logging and error handling
- Extensible design for adding new detectors

Usage:
    python phishing_detector.py <url> [--verbose]
    python phishing_detector.py --batch urls.txt

This tool is for educational and defensive purposes only.
"""

import re
import logging
import argparse
import json
from urllib.parse import urlparse
from typing import Dict, List, Tuple
import ssl
import socket
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingDetector:
    """Main class for phishing detection with multiple analysis modules."""

    def __init__(self, check_ssl: bool = False, verbose: bool = False):
        self.check_ssl = check_ssl
        self.verbose = verbose
        # Common phishing indicators
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'}
        self.suspicious_keywords = {
            'login', 'signin', 'account', 'verify', 'secure', 'update', 
            'bank', 'paypal', 'instagram', 'facebook', 'apple', 'microsoft',
            'amazon', 'netflix', 'chase', 'wellsfargo', 'ebay', 'paypal'
        }
        self.shortener_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 't.co'
        }
        # Unicode confusables mapping (simplified for demonstration)
        self.homograph_map = {
            'а': 'a',  # Cyrillic a
            'е': 'e',  # Cyrillic e
            'о': 'o',  # Cyrillic o
            'р': 'p',  # Cyrillic p
            'с': 'c',  # Cyrillic c
            'у': 'y',  # Cyrillic y
            'х': 'x',  # Cyrillic x
        }

    def check_url(self, url: str) -> Dict:
        """
        Analyze a URL and return a risk assessment.
        Returns a dict with score, level, reasons, and optional SSL info.
        """
        result = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'Low',
            'reasons': [],
            'ssl_valid': None,
            'ssl_details': None
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path  # Handle missing scheme
            if not domain:
                result['reasons'].append("Invalid URL: no domain found")
                result['risk_score'] += 5
                return self._finalize(result)

            # Run all checks
            self._check_ip_address(domain, result)
            self._check_suspicious_tld(domain, result)
            self._check_url_shortener(domain, result)
            self._check_suspicious_keywords(domain, parsed.path, result)
            self._check_excessive_subdomains(domain, result)
            self._check_at_symbol(url, result)
            self._check_https(parsed.scheme, result)
            self._check_homograph(domain, result)

            # Optional SSL certificate validation
            if self.check_ssl and parsed.scheme == 'https':
                self._check_ssl_cert(domain, result)

        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            result['reasons'].append(f"Analysis error: {str(e)}")
            result['risk_score'] += 1  # Minor penalty for errors

        return self._finalize(result)

    def _finalize(self, result: Dict) -> Dict:
        """Set risk level based on score."""
        score = result['risk_score']
        if score < 3:
            result['risk_level'] = 'Low'
        elif score < 6:
            result['risk_level'] = 'Medium'
        else:
            result['risk_level'] = 'High'
        return result

    def _check_ip_address(self, domain: str, result: Dict):
        """Check if domain is an IP address."""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            # Optional: validate IP ranges
            parts = domain.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                result['risk_score'] += 3
                result['reasons'].append("URL uses an IP address instead of a domain name.")

    def _check_suspicious_tld(self, domain: str, result: Dict):
        """Check for TLDs commonly used in phishing."""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result['risk_score'] += 2
                result['reasons'].append(f"Domain uses suspicious TLD: {tld}")
                break

    def _check_url_shortener(self, domain: str, result: Dict):
        """Check if domain is a known URL shortener."""
        for short in self.shortener_domains:
            if short in domain:
                result['risk_score'] += 2
                result['reasons'].append("URL uses a link shortener (hides actual destination).")
                break

    def _check_suspicious_keywords(self, domain: str, path: str, result: Dict):
        """Check for keywords commonly found in phishing URLs."""
        combined = (domain + ' ' + path).lower()
        found = []
        for kw in self.suspicious_keywords:
            if kw in combined:
                found.append(kw)
        if found:
            result['risk_score'] += len(found)  # Increment per keyword
            result['reasons'].append(f"Contains suspicious keywords: {', '.join(found)}")

    def _check_excessive_subdomains(self, domain: str, result: Dict):
        """Check for too many subdomains (possible mimicry)."""
        if domain.count('.') > 3:
            result['risk_score'] += 1
            result['reasons'].append("Excessive subdomains (may be trying to mimic legitimate site).")

    def _check_at_symbol(self, url: str, result: Dict):
        """Check for '@' which can indicate a redirect."""
        if '@' in url:
            result['risk_score'] += 2
            result['reasons'].append("Contains '@' symbol, which can be used for redirects.")

    def _check_https(self, scheme: str, result: Dict):
        """Check if HTTPS is used."""
        if scheme != 'https':
            result['risk_score'] += 1
            result['reasons'].append("Does not use HTTPS (unencrypted connection).")

    def _check_homograph(self, domain: str, result: Dict):
        """Detect possible homograph attacks using Unicode."""
        # Normalize domain to ASCII-compatible form
        try:
            ascii_domain = domain.encode('idna').decode('ascii')
            if ascii_domain != domain:
                # Domain contains non-ASCII characters, potential homograph
                result['risk_score'] += 2
                result['reasons'].append(f"Domain uses non-ASCII characters (possible homograph attack). ASCII form: {ascii_domain}")
                # Check for specific confusables
                for char in domain:
                    if char in self.homograph_map:
                        result['reasons'].append(f"  - Character '{char}' could be confused with '{self.homograph_map[char]}'")
        except UnicodeError:
            # Invalid IDNA, might be malicious
            result['risk_score'] += 2
            result['reasons'].append("Domain contains invalid Unicode (possible attack).")

    def _check_ssl_cert(self, domain: str, result: Dict):
        """Validate SSL certificate of the domain."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
            # Check expiration
            exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if exp_date < datetime.now():
                result['risk_score'] += 3
                result['reasons'].append("SSL certificate is expired.")
            else:
                result['ssl_valid'] = True
                if self.verbose:
                    result['ssl_details'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': exp_date.isoformat()
                    }
        except Exception as e:
            result['risk_score'] += 2
            result['reasons'].append(f"SSL certificate validation failed: {str(e)}")
            result['ssl_valid'] = False

    def display_report(self, result: Dict):
        """Pretty print the analysis report."""
        print("=" * 70)
        print(f"URL: {result['url']}")
        print(f"Risk Score: {result['risk_score']} ({result['risk_level']})")
        if result['reasons']:
            print("Indicators:")
            for reason in result['reasons']:
                print(f"  • {reason}")
        else:
            print("No obvious phishing indicators detected.")
        if result['ssl_valid'] is not None:
            print(f"SSL Valid: {result['ssl_valid']}")
        if result['ssl_details'] and self.verbose:
            print(f"SSL Details: {json.dumps(result['ssl_details'], indent=2)}")
        print("=" * 70)

def batch_process(file_path: str, detector: PhishingDetector):
    """Process multiple URLs from a file."""
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            report = detector.check_url(url)
            detector.display_report(report)
            print()  # Blank line between reports
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except Exception as e:
        logger.error(f"Error processing batch file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Phishing URL Detector - Educational Tool")
    parser.add_argument("url", nargs="?", help="Single URL to analyze")
    parser.add_argument("--batch", "-b", metavar="FILE", help="Batch process URLs from a file")
    parser.add_argument("--check-ssl", action="store_true", help="Validate SSL certificates (slower)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    args = parser.parse_args()

    detector = PhishingDetector(check_ssl=args.check_ssl, verbose=args.verbose)

    if args.batch:
        batch_process(args.batch, detector)
    elif args.url:
        report = detector.check_url(args.url)
        detector.display_report(report)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()