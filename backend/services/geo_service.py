"""
GeoLocation Service
IP-to-City/Country/ASN lookup using MaxMind GeoLite2 with ipapi.co fallback
"""

import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# GeoIP database path
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'GeoLite2-City.mmdb')

# Risk-weighted country tiers (higher = more suspicious for phishing origin)
COUNTRY_RISK_TIER = {
    # Tier 1: Common hosting / low risk
    'US': 1, 'GB': 1, 'DE': 1, 'FR': 1, 'CA': 1, 'AU': 1, 'JP': 1, 'NL': 1,
    # Tier 2: Moderate risk
    'RU': 2, 'CN': 2, 'BR': 2, 'IN': 2, 'KR': 2, 'SG': 2,
    # Tier 3: Higher risk (frequently abused hosting)
    'UA': 3, 'RO': 3, 'BG': 3, 'ID': 3, 'VN': 3, 'TH': 3, 'PH': 3,
    # Tier 4: Highest risk (bulletproof hosting, abuse hubs)
    'MD': 4, 'PA': 4, 'SC': 4, 'BZ': 4, 'CR': 4, 'HN': 4,
}

# Known hosting ASNs (cloud/VPS providers often used for phishing)
HOSTING_ASNS = {
    'Amazon AWS', 'Amazon.com', 'Google Cloud', 'Microsoft Azure',
    'DigitalOcean', 'Vultr', 'Hetzner', 'OVH', 'Linode', 'Alibaba Cloud',
    'Cloudflare', 'Fastly', 'Akamai', 'BootstrapVPS', 'Contabo',
}


class GeoService:
    """IP geolocation service with MaxMind + ipapi fallback"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or GEOIP_DB_PATH
        self.reader = None
        self._init_maxmind()

    def _init_maxmind(self):
        try:
            import geoip2.database
            if os.path.exists(self.db_path):
                self.reader = geoip2.database.Reader(self.db_path)
                logger.info(f"MaxMind GeoLite2 loaded from {self.db_path}")
            else:
                logger.warning(f"GeoLite2 database not found at {self.db_path} — using ipapi fallback only")
        except ImportError:
            logger.warning("geoip2 not installed — using ipapi fallback only")

    def lookup_ip(self, ip: str) -> Dict:
        """
        Look up IP address and return geo + ASN data.
        Returns: {
            'ip': str,
            'city': str, 'country': str, 'country_code': str,
            'latitude': float, 'longitude': float,
            'asn': str, 'org': str, 'is_hosting': bool,
            'risk_tier': int, 'risk_score': int,
            'source': 'maxmind' | 'ipapi' | 'unknown'
        }
        """
        result = {
            'ip': ip,
            'city': 'Unknown', 'country': 'Unknown', 'country_code': 'XX',
            'latitude': 0.0, 'longitude': 0.0,
            'asn': 'Unknown', 'org': 'Unknown', 'is_hosting': False,
            'risk_tier': 0, 'risk_score': 0,
            'source': 'unknown'
        }

        # Try MaxMind first
        if self.reader:
            try:
                response = self.reader.city(ip)
                result.update({
                    'city': response.city.name or 'Unknown',
                    'country': response.country.name or 'Unknown',
                    'country_code': response.country.iso_code or 'XX',
                    'latitude': response.location.latitude or 0.0,
                    'longitude': response.location.longitude or 0.0,
                    'source': 'maxmind'
                })
            except Exception as e:
                logger.debug(f"MaxMind lookup failed for {ip}: {e}")

        # Fallback to ipapi if MaxMind didn't work
        if result['source'] == 'unknown':
            result = self._ipapi_lookup(ip, result)

        # Enrich with ASN data
        result = self._enrich_asn(ip, result)

        # Calculate risk score
        result['risk_tier'] = COUNTRY_RISK_TIER.get(result['country_code'], 2)
        result['risk_score'] = self._calculate_risk_score(result)

        return result

    def _ipapi_lookup(self, ip: str, result: Dict) -> Dict:
        """Fallback: free ipapi.co lookup (1000 req/day)"""
        import httpx
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f'https://ipapi.co/{ip}/json/')
                if resp.status_code == 200:
                    data = resp.json()
                    result.update({
                        'city': data.get('city', 'Unknown'),
                        'country': data.get('country_name', 'Unknown'),
                        'country_code': data.get('country_code', 'XX'),
                        'latitude': data.get('latitude', 0.0),
                        'longitude': data.get('longitude', 0.0),
                        'asn': data.get('asn', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'source': 'ipapi'
                    })
        except Exception as e:
            logger.debug(f"ipapi lookup failed for {ip}: {e}")
        return result

    def _enrich_asn(self, ip: str, result: Dict) -> Dict:
        """Enrich with ASN data from MaxMind or ipapi"""
        if self.reader and result['asn'] == 'Unknown':
            try:
                import geoip2.database
                # GeoLite2-ASN is a separate database
                asn_db_path = self.db_path.replace('City', 'ASN')
                if os.path.exists(asn_db_path):
                    asn_reader = geoip2.database.Reader(asn_db_path)
                    asn_response = asn_reader.asn(ip)
                    result['asn'] = str(asn_response.autonomous_system_number)
                    result['org'] = asn_response.autonomous_system_organization or 'Unknown'
                    asn_reader.close()
            except Exception:
                pass

        # Check if it's a hosting provider
        org_lower = result.get('org', '').lower()
        result['is_hosting'] = any(provider.lower() in org_lower for provider in HOSTING_ASNS)

        return result

    def _calculate_risk_score(self, data: Dict) -> int:
        """Calculate geo-based risk score (0-100)"""
        score = 0

        # Country risk (0-40)
        tier = data.get('risk_tier', 2)
        score += tier * 10

        # Hosting provider risk (0-20) — hosting is common for phishing infra
        if data.get('is_hosting'):
            score += 20

        # Unknown location (0-15)
        if data.get('country_code') == 'XX':
            score += 15

        return min(100, score)

    def lookup_domain(self, domain: str) -> Dict:
        """Resolve domain to IP, then lookup geo"""
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip = str(answers[0])
            return self.lookup_ip(ip)
        except Exception as e:
            logger.debug(f"DNS resolution failed for {domain}: {e}")
            return {'ip': None, 'error': str(e), 'risk_score': 0, 'source': 'dns_failed'}

    def close(self):
        if self.reader:
            self.reader.close()


# Singleton
_geo_service: Optional[GeoService] = None


def get_geo_service() -> GeoService:
    global _geo_service
    if _geo_service is None:
        _geo_service = GeoService()
    return _geo_service
