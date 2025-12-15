import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse
import socket
import argparse
import re

# ANSI Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def remove_ansi_codes(text):
    """Removes ANSI escape sequences from text for file output."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

class TeeLogger:
    """Writes output to both stdout (with colors) and a file (clean text)."""
    def __init__(self, filename=None):
        self.terminal = sys.stdout
        self.filename = filename
        self.file = open(filename, 'w', encoding='utf-8') if filename else None

    def log(self, message, end='\n'):
        # 1. Print to terminal (with colors)
        print(message, end=end, file=self.terminal)
        
        # 2. Write to file (without colors)
        if self.file:
            clean_message = remove_ansi_codes(message)
            self.file.write(clean_message + end)

    def close(self):
        if self.file:
            self.file.close()

# Global logger instance
logger = None

def print_log(message, end='\n'):
    """Helper to log to both destinations."""
    if logger:
        logger.log(message, end)
    else:
        print(message, end=end)

def normalize_url(url):
    """Ensures the URL has a scheme (https by default)."""
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"https://{url}"
    return url

def validate_header_value(header_key, value):
    """
    Analyzes specific header values for security weaknesses.
    Returns: (is_secure, message)
      is_secure: True (Pass), False (Fail), or None (Warning)
    """
    value = value.lower()

    # 1. Strict-Transport-Security (HSTS)
    if header_key == 'strict-transport-security':
        age_match = re.search(r'max-age=(\d+)', value)
        if age_match:
            seconds = int(age_match.group(1))
            if seconds < 31536000: # Less than 1 year (365 days)
                return False, f"Value: {value} (Weak: max-age is less than 1 year)"
            if 'includesubdomains' not in value:
                return False, f"Value: {value} (Weak: missing 'includeSubDomains')"
            return True, f"Value: {value} (Strong)"
        return False, f"Value: {value} (Invalid: max-age missing)"

    # 2. X-Content-Type-Options
    if header_key == 'x-content-type-options':
        if value.strip() == 'nosniff':
            return True, f"Value: {value}"
        return False, f"Value: {value} (Insecure: Must be 'nosniff')"

    # 3. X-Frame-Options
    if header_key == 'x-frame-options':
        if value.upper() in ['DENY', 'SAMEORIGIN']:
            return True, f"Value: {value}"
        return False, f"Value: {value} (Insecure: Should be DENY or SAMEORIGIN)"

    # 4. X-Permitted-Cross-Domain-Policies
    if header_key == 'x-permitted-cross-domain-policies':
        if value.strip() == 'none':
            return True, f"Value: {value}"
        if value.strip() == 'master-only':
            return None, f"Value: {value} (Acceptable, but 'none' is preferred)"
        return False, f"Value: {value} (Insecure: Should be 'none')"

    # 5. Referrer-Policy
    if header_key == 'referrer-policy':
        secure_policies = [
            'no-referrer', 'same-origin', 'strict-origin',
            'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin'
        ]
        provided_policies = [p.strip() for p in value.split(',')]
        for p in provided_policies:
            if p not in secure_policies:
                return False, f"Value: {value} (Insecure policy detected: {p})"
        return True, f"Value: {value}"

    # 6. Content-Security-Policy (CSP)
    if header_key == 'content-security-policy':
        issues = []
        if 'unsafe-inline' in value:
            issues.append("'unsafe-inline'")
        if 'unsafe-eval' in value:
            issues.append("'unsafe-eval'")
        if 'default-src *' in value:
            issues.append("'default-src *'")
        
        display_val = (value[:60] + '..') if len(value) > 60 else value
        
        if issues:
            return None, f"Value: {display_val} (Warning: Contains {', '.join(issues)})"
        return True, f"Value: {display_val}"

    # 7. Cross-Origin Headers (COOP, COEP, CORP)
    if header_key in ['cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy']:
        if 'unsafe-none' in value:
            return False, f"Value: {value} (Insecure: 'unsafe-none' allows cross-origin attacks)"
        return True, f"Value: {value}"

    return True, f"Found"


def check_headers(url):
    """Checks the target headers for a specific URL."""
    url = normalize_url(url)
    print_log(f"\n{BOLD}Analyzing: {url}{RESET}")
    print_log("-" * 60)

    # 1. Request Logic (HEAD -> GET Fallback)
    response = None
    try:
        req_head = urllib.request.Request(
            url, 
            headers={'User-Agent': 'SecOps-Scanner/1.0'}, 
            method='HEAD'
        )
        response = urllib.request.urlopen(req_head, timeout=10)
    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as e:
        try:
            req_get = urllib.request.Request(
                url, 
                headers={'User-Agent': 'SecOps-Scanner/1.0'}, 
                method='GET'
            )
            response = urllib.request.urlopen(req_get, timeout=10)
        except Exception as e:
            print_log(f"{RED}Failed to connect: {e}{RESET}")
            return

    # 2. Analysis Logic
    if response:
        # Check for Redirects
        final_url = response.geturl()
        if final_url != url:
            print_log(f"{BLUE}ℹ Note: Redirected to {final_url}{RESET}")
        else:
             print_log(f"{BLUE}ℹ Effective URL: {final_url}{RESET}")

        server_headers = {k.lower(): v for k, v in response.headers.items()}
        
        target_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-Permitted-Cross-Domain-Policies",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
            "Clear-Site-Data"
        ]

        all_passed = True

        print_log(f"\n{BOLD}Security Headers:{RESET}")
        for header in target_headers:
            header_key = header.lower()
            
            if header_key in server_headers:
                raw_value = server_headers[header_key]
                is_secure, message = validate_header_value(header_key, raw_value)
                
                if is_secure is True:
                    print_log(f"[{GREEN}✓{RESET}] {header:<35} : {GREEN}{message}{RESET}")
                elif is_secure is False:
                    print_log(f"[{RED}✗{RESET}] {header:<35} : {RED}{message}{RESET}")
                    all_passed = False
                else: # None = Warning
                    print_log(f"[{YELLOW}!{RESET}] {header:<35} : {YELLOW}{message}{RESET}")
            else:
                print_log(f"[{RED}✗{RESET}] {header:<35} : {RED}MISSING{RESET}")
                all_passed = False

        # 3. Cookie Check
        cookies = response.headers.get_all('Set-Cookie') or []
        if cookies:
            print_log(f"\n{BOLD}Cookie Analysis:{RESET}")
            for cookie in cookies:
                name = cookie.split('=')[0]
                flags = []
                if 'secure' not in cookie.lower(): flags.append(f"Missing Secure")
                if 'httponly' not in cookie.lower(): flags.append(f"Missing HttpOnly")
                if 'samesite' not in cookie.lower(): flags.append(f"Missing SameSite")
                
                if not flags:
                    print_log(f"  [{GREEN}✓{RESET}] {name}: Secure, HttpOnly, SameSite present")
                else:
                    # Note: We color the X red but keep the text simpler for readability
                    print_log(f"  [{RED}✗{RESET}] {name}: {RED}{', '.join(flags)}{RESET}")
                    all_passed = False
        else:
            print_log(f"\n{BLUE}ℹ No Set-Cookie headers found (Standard for stateless APIs){RESET}")

        if all_passed:
            print_log(f"\n{GREEN}RESULT: Perfect Score! All headers are secure.{RESET}")
        else:
            print_log(f"\n{RED}RESULT: Issues detected. See above for details.{RESET}")

def main():
    global logger
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Audit security headers for a list of domains.")
    parser.add_argument("domains", nargs="+", help="The domain(s) or URLs to scan")
    parser.add_argument("-o", "--output", help="Save the report to a text file (ANSI colors stripped)", default=None)
    
    args = parser.parse_args()

    # Initialize the logger
    logger = TeeLogger(args.output)
    
    try:
        for domain in args.domains:
            check_headers(domain)
    finally:
        logger.close()
        if args.output:
            print(f"\n{BLUE}Report saved to: {args.output}{RESET}")

if __name__ == "__main__":
    main()
