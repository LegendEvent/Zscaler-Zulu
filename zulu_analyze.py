import requests
import re
import json
from urllib.parse import urljoin, urlparse
import argparse

class ZuluZscaler:
    """
    Automated analysis of URLs with Zulu Zscaler.
    For open source: You can provide your own safe domains list.
    """
    DEFAULT_SAFE_DOMAINS = [
        "example.com",
        "example.org",
        "example.net",
        "testdomain.local",
        "mycompany.com"
    ]

    def __init__(self, default_safe_domains: list[str] = None, verify_ssl: bool = True):
        """
        default_safe_domains: Optional custom list of safe domains (overrides DEFAULT_SAFE_DOMAINS)
        verify_ssl: Enable or disable SSL certificate verification (default: True)
        """
        self.safe_domains = default_safe_domains if default_safe_domains is not None else self.DEFAULT_SAFE_DOMAINS
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.base_url = 'https://zulu.zscaler.com'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Ch-Ua': '"Microsoft Edge";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
        }
        self.csrf_token = None

    def init_session(self) -> str:
        """Initialize session and get initial cookies and CSRF token"""
        response = self.session.get(self.base_url, headers=self.headers)
        
        csrf_patterns = [
            r'name="csrf_token"\s+value="([^"]+)"',
            r'name="csrf-token" content="([^"]+)"',
            r'name="_csrf" value="([^"]+)"',
            r'csrf-token:\s*["\']([^"]+)["\']'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, response.text)
            if match:
                self.csrf_token = match.group(1)
                break
        
        return response.text

    def is_safe_domain(self, url: str) -> bool:
        """Check if the domain is in the known safe domains list"""
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            domain = urlparse(url).netloc.lower()
            if not domain:  # If netloc is empty, the URL itself might be the domain
                domain = url.lower()
            
            # Remove 'www.' if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            return domain in self.safe_domains
        except Exception as e:
            print(f"Error in is_safe_domain: {str(e)}")
            return False

    def analyze_url(self, url: str) -> dict:
        """Analyze a URL using Zulu Zscaler and return result as dict"""
        # Ensure URL has a scheme for the analysis
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Check if URL is from a known safe domain
        if self.is_safe_domain(url):
            return {
                'url': url,
                'status': 'safe',
                'message': 'Domain is in the known safe list'
            }

        main_page = self.init_session()
        
        form_pattern = r'<form[^>]*action="([^"]+)"[^>]*>'
        form_match = re.search(form_pattern, main_page)
        
        if form_match:
            analyze_endpoint = form_match.group(1)
            if not analyze_endpoint.startswith('http'):
                analyze_endpoint = urljoin(self.base_url, analyze_endpoint)
        else:
            analyze_endpoint = urljoin(self.base_url, '/')

        headers = {
            **self.headers,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://zulu.zscaler.com',
            'Referer': self.base_url
        }

        if self.csrf_token:
            headers['X-CSRF-Token'] = self.csrf_token

        data = {
            'url': url,
            'csrf_token': self.csrf_token
        }

        response = self.session.post(
            analyze_endpoint,
            headers=headers,
            data=data,
            allow_redirects=True
        )

        result = {
            'url': url,
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type')
        }

        # Extract last performed date
        performed_match = re.search(r'Performed on ([^<]+)', response.text)
        if performed_match:
            result['last_performed'] = performed_match.group(1).strip()

        # Extract score and classification
        score_match = re.search(r'<span id="jscore"[^>]*>(\d+)</span>', response.text)
        if score_match:
            result['score'] = int(score_match.group(1))
            
        class_match = re.search(r'<span class="report-icon [^"]+">([^<]+)</span>', response.text)
        if class_match:
            result['classification'] = class_match.group(1)

        # Extract Analysis section
        analysis = {}
        
        # Basic Analysis
        fields = {
            'redirections': r'id="rep-redir">([^<]+)</span>',
            'http_status': r'id="rep-code">([^<]+)</span>',
            'content_size': r'id="rep-size">([^<]+)</span>',
            'content_type': r'id="rep-cont-type">([^<]+)</span>',
            'ip_address': r'id="rep-ip">([^<]+)</span>',
            'country': r'id="rep-country">([^<]+)</span>',
            'web_server': r'id="rep-web-server">([^<]+)</span>'
        }
        
        for key, pattern in fields.items():
            match = re.search(pattern, response.text)
            if match:
                analysis[key] = match.group(1).strip()

        # Domain History
        domain_history = []
        history_pattern = r'<p class="" id="rep-domain-hist">\s*<span class="first fg-color-mid-gray">([^<]+)</span>\s*<span class="second[^"]*"><a href="([^"]+)">([^<]+)</a></span>'
        for match in re.finditer(history_pattern, response.text):
            domain_history.append({
                'date': match.group(1).strip(),
                'report_id': match.group(2).strip('/report/'),
                'url': match.group(3).strip(' ..')
            })
        if domain_history:
            analysis['domain_history'] = domain_history

        result['analysis'] = analysis

        # Extract sections with checks
        sections = {
            'external_elements': 'External Elements</h1>',
            'content_checks': 'Content Checks</h1>',
            'url_checks': 'URL Checks</h1>',
            'host_checks': 'Host Checks</h1>'
        }

        for section_key, section_header in sections.items():
            items = []
            # Fix escape sequence and improve pattern to find table content
            section_pattern = f'<h1 class="margin-bottom-16">{section_header.replace("</h1>", "")}.*?<table.*?<tbody.*?>(.*?)</tbody>'
            section = re.search(section_pattern, response.text, re.DOTALL)
            
            if section:
                if section_key == 'external_elements':
                    # Pattern for external elements with links
                    pattern = r'<tr>\s*<td class="link"><a[^>]*>([^<]+)</a></td>\s*<td><span[^>]*>([^<]+)</span></td>\s*</tr>'
                    for match in re.finditer(pattern, section.group(1)):
                        items.append({
                            'url': match.group(1).strip(' ..'),
                            'risk': match.group(2).strip()
                        })
                else:
                    # Pattern for Content, URL and Host Checks - considers empty descriptions
                    pattern = r'<tr>\s*<td[^>]*><span class="report-icon-after">([^<]+)</span></td>\s*<td>([^<]*)</td>\s*<td class="fixed">([^<]+)</td>\s*</tr>'
                    for match in re.finditer(pattern, section.group(1)):
                        test = match.group(1).strip()
                        description = match.group(2).strip()
                        risk = match.group(3).strip()
                        items.append({
                            'test': test,
                            'description': description,
                            'risk': risk
                        })
            if items:
                result[section_key] = items

        return result


def main():
    """
    Example usage for CLI and as a module. You can provide your own safe domains via --safe-domains.
    """
    parser = argparse.ArgumentParser(description="Analyze URLs with Zulu Zscaler.")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--safe-domains", nargs="*", default=None, help="List of known safe domains (optional)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification (not recommended)")
    args = parser.parse_args()

    zulu = ZuluZscaler(default_safe_domains=args.safe_domains, verify_ssl=not args.no_verify)
    try:
        result = zulu.analyze_url(args.url)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}")
        print("\nNote: Check if the Zulu Zscaler website is reachable and you are not hitting rate limits.")
        raise

if __name__ == "__main__":
    main()