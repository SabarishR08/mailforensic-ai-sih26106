"""
Advanced URL Preprocessing & Intelligence Service for MailForensic
Normalize, unshorten, extract components, detect threats, homoglyphs, and redirects.
"""

import re
import logging
import requests
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class URLPreprocessor:
    """Preprocess and normalize URLs"""

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for consistent analysis"""
        if not url:
            return ""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if url.endswith('/') and url.count('/') > 3:
            url = url.rstrip('/')

        # Remove common tracking parameters
        tracking_params = [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
            'fbclid', 'gclid', 'msclkid', 'ptaid', 'ref'
        ]

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in tracking_params:
                params.pop(param, None)

            new_query = '&'.join(f"{k}={v[0]}" for k, v in params.items())
            if new_query:
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            else:
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception as e:
            logger.debug(f"Normalization warning for {url}: {e}")

        return url

    @staticmethod
    def extract_components(url: str) -> Dict:
        """Extract URL components"""
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme,
                'domain': parsed.netloc.lower(),
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
            }
        except Exception:
            return {'scheme': '', 'domain': '', 'path': '', 'query': '', 'fragment': ''}

    @staticmethod
    def unshorten_url(url: str, timeout: int = 4) -> str:
        """Resolve shortened URL to final destination safely"""
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
            'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'
        ]

        parsed = urlparse(url)
        if not any(domain in parsed.netloc.lower() for domain in shortener_domains):
            return url

        try:
            response = requests.head(url, allow_redirects=True, timeout=timeout, headers={'User-Agent': 'MailForensic-Scanner/1.0'})
            return response.url
        except Exception as e:
            logger.warning(f"Failed to unshorten URL {url}: {e}")
            return url

    @staticmethod
    def has_redirect_chain(url: str, timeout: int = 3) -> Tuple[bool, List[str]]:
        """
        Check if URL has a redirect chain
        Returns: (has_redirects, [chain of URLs])
        """
        chain = [url]
        try:
            current_url = url
            for _ in range(5):  # Max 5 hops to prevent loop
                response = requests.head(
                    current_url, allow_redirects=False, timeout=timeout,
                    headers={'User-Agent': 'MailForensic-Scanner/1.0'}, verify=False
                )
                if 300 <= response.status_code < 400:
                    redirect_url = response.headers.get('location')
                    if not redirect_url:
                        break
                    if not redirect_url.startswith('http'):
                        parsed = urlparse(chain[-1])
                        redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                    chain.append(redirect_url)
                    current_url = redirect_url
                else:
                    break
            return len(chain) > 1, chain
        except Exception as e:
            logger.warning(f"Redirect check error for {url}: {e}")
            return False, [url]


class URLThreatDetector:
    """Detect threats and risk signals in URLs"""

    SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'download', 'review', 'zip', 'click', 'top', 'xyz', 'work', 'country']

    MALICIOUS_PATTERNS = [
        r'cmd=.*&',         # Command injection
        r'exec\(',          # Code execution
        r'eval\(',          # JavaScript eval
        r'system\(',        # System command
        r'base64_decode',   # Encoded payload
        r'login.*verify',   # Phishing parameters
    ]

    HOMOGLYPH_CHARS = set('абвгдежзийклмнопрстуфхцчшщъыьэюяäöüàáâãäåæçèéêëìíîïñòóôõöøùúûüýÿ')

    @classmethod
    def detect_threats(cls, url: str) -> Dict:
        """
        Detect threat indicators in URL
        Returns: {threats: [], risk_level: '', risk_score: 0}
        """
        threats = []
        risk_score = 0

        if not url:
            return {'threats': threats, 'risk_level': 'low', 'risk_score': 0}

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return {'threats': ['Invalid URL structure'], 'risk_level': 'medium', 'risk_score': 50}

        # 1. IP-based URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            threats.append('IP-based URL (no domain)')
            risk_score += 25

        # 2. Suspicious TLD
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1]
            if tld in cls.SUSPICIOUS_TLDS:
                threats.append(f'Suspicious TLD: .{tld}')
                risk_score += 20

        # 3. Domain WHOIS Age
        try:
            import whois
            domain_info = whois.whois(domain)
            if domain_info and domain_info.creation_date:
                creation = domain_info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    days_old = (datetime.now() - creation).days
                    if days_old < 30:
                        threats.append(f'Recently registered domain ({days_old} days old)')
                        risk_score += 30
                    elif days_old < 365:
                        threats.append(f'Young domain ({days_old} days old)')
                        risk_score += 15
        except Exception:
            pass

        # 4. Homoglyph check
        if cls._has_homoglyph(domain):
            threats.append('Potential homoglyph attack (look-alike domain)')
            risk_score += 35

        # 5. Punycode check
        if 'xn--' in domain:
            threats.append('Punycode domain (potential spoofing)')
            risk_score += 30

        # 6. Excessive subdomains
        if domain.count('.') > 3:
            threats.append('Excessive subdomains (suspicious)')
            risk_score += 15

        # 7. Unusually long domain
        if len(domain) > 50:
            threats.append('Unusually long domain')
            risk_score += 10

        # 8. Encoded suspicious keywords
        if '%' in url and any(keyword in unquote(url).lower() for keyword in ['login', 'password', 'admin', 'verify']):
            threats.append('Encoded suspicious keywords in URL')
            risk_score += 25

        # 9. Malicious patterns
        for pattern in cls.MALICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                threats.append(f'Malicious pattern detected: {pattern}')
                risk_score += 30

        # 10. Direct executable download
        download_extensions = ['.exe', '.msi', '.dmg', '.zip', '.rar', '.bat', '.scr', '.vbs', '.ps1', '.iso', '.pdf.exe']
        if any(path.endswith(ext) for ext in download_extensions):
            threats.append('Direct executable / payload download link')
            risk_score += 40

        # 11. Phishing keywords in path
        phishing_keywords = ['login', 'verify', 'confirm', 'update', 'secure', 'account', 'banking', 'signin', 'auth']
        if any(keyword in path for keyword in phishing_keywords):
            threats.append('Phishing keywords in URL path')
            risk_score += 20

        # 12. TOR / Onion
        if '.onion' in domain:
            threats.append('TOR onion address')
            risk_score += 50

        # 13. Data URI
        if url.startswith('data:'):
            threats.append('Data URI (embedded content payload)')
            risk_score += 25

        final_score = min(risk_score, 100)
        risk_level = 'low' if final_score < 30 else 'medium' if final_score < 60 else 'high' if final_score < 80 else 'critical'

        return {
            'threats': threats,
            'risk_level': risk_level,
            'risk_score': final_score,
        }

    @classmethod
    def _has_homoglyph(cls, domain: str) -> bool:
        """Check if domain contains non-ASCII lookalike characters"""
        for char in domain:
            if char in cls.HOMOGLYPH_CHARS:
                return True
        return False

    @classmethod
    def check_reputation(cls, domain: str) -> Dict:
        """Check basic domain reputation flags"""
        reputation = {'reputable': True, 'sources': {}}
        suspicious_domains = ['bit.ly', 'tinyurl', 'pastebin', 'zerobin', 'tempmail', 'dispostable']
        if any(susp in domain for susp in suspicious_domains):
            reputation['reputable'] = False
            reputation['sources']['url_shortener_anonymizer'] = 'suspicious'
        return reputation


class URLAnalyzer:
    """Combined URL analysis pipeline"""

    @staticmethod
    def full_analysis(url: str, check_redirects: bool = True) -> Dict:
        """
        Complete URL threat analysis
        """
        normalized_url = URLPreprocessor.normalize_url(url)
        components = URLPreprocessor.extract_components(normalized_url)

        final_url = normalized_url
        has_redirects = False
        redirect_chain = [normalized_url]

        if check_redirects and normalized_url.startswith(('http://', 'https://')):
            final_url = URLPreprocessor.unshorten_url(normalized_url)
            has_redirects, redirect_chain = URLPreprocessor.has_redirect_chain(normalized_url)

        threats = URLThreatDetector.detect_threats(final_url)
        reputation = URLThreatDetector.check_reputation(components.get('domain', ''))

        return {
            'original_url': url,
            'normalized_url': normalized_url,
            'final_url': final_url,
            'components': components,
            'has_redirects': has_redirects,
            'redirect_chain': redirect_chain,
            'threats': threats['threats'],
            'risk_level': threats['risk_level'],
            'risk_score': threats['risk_score'],
            'reputation': reputation,
            'analysis_timestamp': datetime.now().isoformat(),
        }
