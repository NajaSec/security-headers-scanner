from colorama import Fore, init
import requests
import sys
from urllib.parse import urlparse
import warnings
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

warnings.filterwarnings('ignore')
init(autoreset=True)

class SecurityHeaderAnalyzer:
    def __init__(self, url, timeout=15, user_agent=None, type_req="GET", max_retries=2):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        self.security_score = 0 
        self.findings = []
        self.type_req = type_req.upper() if type_req else "GET"
        self.max_retries = max_retries
        self.session = self._create_session()

    def _create_session(self):
        """Create a session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def normalize_url(self, url):
        """Add https if no scheme provided"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url
    
    def analyze_header(self):  
        """Fetch and analyze security headers"""
        # Try HTTPS first, then fallback to HTTP if needed
        protocols_to_try = [self.url]
        
        # If URL is HTTPS, also try HTTP as fallback
        if self.url.startswith('https://'):
            http_version = self.url.replace('https://', 'http://')
            protocols_to_try.append(http_version)
        
        for attempt, target_url in enumerate(protocols_to_try):
            try:
                print(f"\n{Fore.CYAN}[*] Attempting to connect to: {target_url}")
                
                headers = {'User-Agent': self.user_agent}
                
                response = self.session.request(
                    method=self.type_req,
                    url=target_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                print(f"\n{Fore.CYAN}{'='*60}")
                print(f"{Fore.YELLOW}🔍 Target: {target_url}")
                print(f"{Fore.GREEN}✓ Status Code: {response.status_code}")
                print(f"{Fore.CYAN}{'='*60}")

                print(f"\n{Fore.GREEN}📤 Request Headers Sent:")
                for key, value in response.request.headers.items():
                    print(f"  {Fore.WHITE}{key}: {value}")

                print(f"\n{Fore.BLUE}📥 Response Headers Received:")
                self.check_security_headers(response.headers)

                self.check_information_disclosure(response)
                self.check_ssl_security(target_url)
                
                self.display_score()
                
                return response.headers

            except requests.exceptions.Timeout:
                print(f"{Fore.YELLOW}⚠️  Timeout on attempt {attempt + 1}/{len(protocols_to_try)}")
                if attempt == len(protocols_to_try) - 1:
                    print(f"{Fore.RED}❌ All connection attempts timed out.")
                    self._show_troubleshooting_tips(target_url)
                    return None
                    
            except requests.exceptions.ConnectionError as e:
                print(f"{Fore.YELLOW}⚠️  Connection error: {str(e)[:100]}")
                if attempt == len(protocols_to_try) - 1:
                    print(f"{Fore.RED}❌ Failed to establish connection.")
                    self._show_troubleshooting_tips(target_url)
                    return None
                    
            except Exception as e:
                print(f"{Fore.RED}❌ Unexpected error: {e}")
                return None
        
        return None
    
    def _show_troubleshooting_tips(self, url):
        """Display troubleshooting tips for connection issues"""
        print(f"\n{Fore.YELLOW}🔧 Troubleshooting Tips:")
        print(f"  • Check your internet connection")
        print(f"  • The website '{url}' might be blocking automated requests")
        print(f"  • Try increasing timeout with --timeout parameter")
        print(f"  • Try using a different User-Agent")
        print(f"  • Check if the website is accessible in your browser")
        print(f"\n{Fore.CYAN}Example with increased timeout:")
        print(f"  python script.py {url} --timeout 30")
        
    def check_security_headers(self, headers):
        """
        Enterprise-grade security headers analyzer with weighted scoring system
        """
        
        security_headers_config = {
            'Strict-Transport-Security': {
                'weight': 25,
                'critical': True,
                'category': 'Transport Security',
                'validation': lambda v: self._validate_hsts(v),
                'recommendation': 'max-age=31536000; includeSubDomains; preload',
                'severity': 'CRITICAL'
            },
            'Content-Security-Policy': {
                'weight': 30,
                'critical': True,
                'category': 'Content Security',
                'validation': lambda v: self._validate_csp(v),
                'recommendation': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
                'severity': 'CRITICAL'
            },
            'X-Frame-Options': {
                'weight': 10,
                'critical': True,
                'category': 'Clickjacking Protection',
                'validation': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'],
                'recommendation': 'DENY or SAMEORIGIN',
                'severity': 'HIGH'
            },
            'X-Content-Type-Options': {
                'weight': 10,
                'critical': True,
                'category': 'MIME Sniffing Protection',
                'validation': lambda v: v.lower() == 'nosniff',
                'recommendation': 'nosniff',
                'severity': 'HIGH'
            },
            'X-XSS-Protection': {
                'weight': 8,
                'critical': False,
                'category': 'Legacy XSS Protection',
                'validation': lambda v: '1; mode=block' in v or '1; mode=block; report=' in v,
                'recommendation': '1; mode=block',
                'severity': 'MEDIUM'
            },
            'Referrer-Policy': {
                'weight': 10,
                'critical': False,
                'category': 'Privacy & Information Leakage',
                'validation': lambda v: v in [
                    'no-referrer', 'same-origin', 'strict-origin', 
                    'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'
                ],
                'recommendation': 'strict-origin-when-cross-origin or no-referrer',
                'severity': 'MEDIUM'
            },
            'Permissions-Policy': {
                'weight': 8,
                'critical': False,
                'category': 'Browser Features Control',
                'validation': lambda v: self._validate_permissions_policy(v),
                'recommendation': "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
                'severity': 'MEDIUM'
            },
            'Cache-Control': {
                'weight': 8,
                'critical': False,
                'category': 'Cache Security',
                'validation': lambda v: 'no-store' in v or 'no-cache' in v or 'private' in v,
                'recommendation': 'no-store, no-cache, private',
                'severity': 'MEDIUM'
            },
            'Access-Control-Allow-Origin': {
                'weight': 10,
                'critical': True,
                'category': 'CORS Security',
                'validation': lambda v: self._validate_cors_origin(v),
                'recommendation': 'Specific origin, never wildcard (*) for sensitive data',
                'severity': 'HIGH'
            }
        }
        
        categories = {
            'Transport Security': {'present': 0, 'total': 0, 'score': 0},
            'Content Security': {'present': 0, 'total': 0, 'score': 0},
            'Clickjacking Protection': {'present': 0, 'total': 0, 'score': 0},
            'MIME Sniffing Protection': {'present': 0, 'total': 0, 'score': 0},
            'Legacy XSS Protection': {'present': 0, 'total': 0, 'score': 0},
            'Privacy & Information Leakage': {'present': 0, 'total': 0, 'score': 0},
            'Browser Features Control': {'present': 0, 'total': 0, 'score': 0},
            'Cache Security': {'present': 0, 'total': 0, 'score': 0},
            'CORS Security': {'present': 0, 'total': 0, 'score': 0}
        }
        
        print(f"\n{Fore.YELLOW}🔒 SECURITY HEADERS ANALYSIS")
        print(f"{Fore.CYAN}{'─'*70}")
        print(f"{'HEADER':<35} {'STATUS':<15} {'SCORE':<10} {'SEVERITY':<10}")
        print(f"{Fore.CYAN}{'─'*70}")
        
        max_possible_score = sum(config['weight'] for config in security_headers_config.values())
        
        for header, config in security_headers_config.items():
            value = headers.get(header)
            category = config['category']
            categories[category]['total'] += 1
            
            if value:
                is_valid = config['validation'](value)
                
                if is_valid:
                    earned_score = config['weight']
                    self.security_score += earned_score
                    categories[category]['present'] += 1
                    categories[category]['score'] += earned_score
                    
                    print(f"{Fore.GREEN}{header:<35} {Fore.GREEN}✓ VALID{Fore.RESET:<10} {Fore.GREEN}+{earned_score:<9}{Fore.RESET} {config['severity']:<10}")
                else:
                    print(f"{Fore.YELLOW}{header:<35} {Fore.YELLOW}⚠ WEAK{Fore.RESET:<10} {Fore.RED}0{Fore.RESET:<9} {config['severity']:<10}")
                    self.findings.append({
                        'header': header,
                        'severity': config['severity'],
                        'issue': 'Present but misconfigured',
                        'recommendation': config['recommendation'],
                        'current_value': value[:100]
                    })
            else:
                severity_color = Fore.RED if config['severity'] == 'CRITICAL' else Fore.YELLOW
                print(f"{severity_color}{header:<35} {Fore.RED}✗ MISSING{Fore.RESET:<9} {Fore.RED}0{Fore.RESET:<9} {config['severity']:<10}")
                
                self.findings.append({
                    'header': header,
                    'severity': config['severity'],
                    'issue': 'Critical security header missing' if config['critical'] else 'Recommended security header missing',
                    'recommendation': config['recommendation'],
                    'current_value': None
                })
        
        # Calculate final percentage
        final_percentage = (self.security_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        print(f"\n{Fore.CYAN}{'─'*70}")
        print(f"{Fore.YELLOW}🎯 SECURITY SCORE: {self.security_score}/{max_possible_score} ({final_percentage:.1f}%)")
        
        if final_percentage >= 90:
            rating = f"{Fore.GREEN}A+ (EXCELLENT) - Enterprise Grade Security"
        elif final_percentage >= 75:
            rating = f"{Fore.LIGHTGREEN_EX}A (GOOD) - Production Ready"
        elif final_percentage >= 60:
            rating = f"{Fore.YELLOW}B (FAIR) - Needs Improvement"
        elif final_percentage >= 40:
            rating = f"{Fore.LIGHTRED_EX}C (POOR) - Security Gaps Detected"
        else:
            rating = f"{Fore.RED}F (CRITICAL) - Immediate Action Required"
        
        print(f"Security Rating: {rating}{Fore.RESET}")

    def _validate_hsts(self, value):
        """Validate HSTS header configuration"""
        value_lower = value.lower()
        if 'max-age' not in value_lower:
            return False
        
        match = re.search(r'max-age=(\d+)', value_lower)
        if match:
            max_age = int(match.group(1))
            if max_age >= 31536000:  # 1 year minimum
                return True
        return False

    def _validate_csp(self, value):
        """Validate Content-Security-Policy header"""
        if not value or len(value) < 20:
            return False
        
        # Check for unsafe-inline (security risk but better than no CSP)
        if "'unsafe-inline'" in value:
            return True
        
        secure_directives = ["default-src", "script-src", "style-src"]
        has_secure_directive = any(directive in value for directive in secure_directives)
        
        return has_secure_directive

    def _validate_permissions_policy(self, value):
        """Validate Permissions-Policy header"""
        restricted_features = ['geolocation=()', 'microphone=()', 'camera=()']
        has_restrictions = any(feature in value for feature in restricted_features)
        return has_restrictions or len(value) > 20

    def _validate_cors_origin(self, value):
        """Validate CORS Access-Control-Allow-Origin header"""
        if value == '*':
            return False
        return value.startswith('http') or value == 'null'

    def check_information_disclosure(self, response):
        """Check for information disclosure vulnerabilities"""
        print(f"\n{Fore.MAGENTA}📋 INFORMATION DISCLOSURE CHECK")
        print(f"{Fore.CYAN}{'─'*50}")
        
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        
        for header in sensitive_headers:
            value = response.headers.get(header)
            if value:
                print(f"{Fore.YELLOW}⚠️  {header}: {value}")
        
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get('Set-Cookie')
            if 'Secure' not in cookies:
                print(f"{Fore.RED}❌ Cookie without Secure flag")
            if 'HttpOnly' not in cookies:
                print(f"{Fore.YELLOW}⚠️  Cookie without HttpOnly flag")

    def check_ssl_security(self, url):
        """Check SSL/TLS configuration"""
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            print(f"\n{Fore.GREEN}🔐 SSL/TLS: Enabled")
        else:
            print(f"\n{Fore.RED}🔓 SSL/TLS: Disabled - Insecure Communication")

    def display_score(self):
        """Display final security score summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}📊 FINAL SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        if self.findings:
            print(f"\n{Fore.YELLOW}⚠️  Total Issues Found: {len(self.findings)}")
            critical_count = len([f for f in self.findings if f.get('severity') == 'CRITICAL'])
            high_count = len([f for f in self.findings if f.get('severity') == 'HIGH'])
            
            if critical_count > 0:
                print(f"{Fore.RED}🔴 Critical: {critical_count}")
            if high_count > 0:
                print(f"{Fore.LIGHTRED_EX}🟠 High: {high_count}")
        else:
            print(f"\n{Fore.GREEN}✓ No security issues detected!")
        
        print(f"{Fore.CYAN}{'='*60}\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Header Analyzer Tool')
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET, POST, etc.)')
    parser.add_argument('-r', '--retries', type=int, default=2, help='Number of retries (default: 2)')
    parser.add_argument('-ua', '--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}")
    print("╔══════════════════════════════════════════╗")
    print("║   Security Header Analyzer Tool v3.0    ║")
    print("║        HTTP Security Scanner             ║")
    print("╚══════════════════════════════════════════╝")
    
    analyzer = SecurityHeaderAnalyzer(
        args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        type_req=args.method,
        max_retries=args.retries
    )
    
    analyzer.analyze_header()


if __name__ == "__main__":
    main()