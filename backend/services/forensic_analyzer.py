"""
Unified Forensic Email Analyzer
Parses email headers, traces routing hops with geo-enrichment,
checks SPF/DKIM/DMARC, and generates trust scores.
Merges logic from header_analyzer.py + email_analyzer.py.
"""

import re
import logging
from typing import Dict, List, Optional
from email import message_from_string
from email.utils import parseaddr

logger = logging.getLogger(__name__)


class ForensicAnalyzer:
    """Deep forensic analysis of email headers and authentication"""

    SUSPICIOUS_KEYWORDS = ['localhost', '127.0.0.1', 'unknown', 'dynamic', 'dhcp']

    def analyze(self, email_text: str, geo_service=None) -> Dict:
        """
        Full forensic analysis of an email.
        Returns a comprehensive forensic report dict.
        """
        try:
            msg = message_from_string(email_text)
        except Exception as e:
            return {'error': str(e), 'trust_score': 0, 'trust_level': 'UNKNOWN'}

        from_addr = self._parse_email_address(msg.get('From', ''))
        reply_to = self._parse_email_address(msg.get('Reply-To', ''))
        return_path = self._parse_email_address(msg.get('Return-Path', ''))

        spf_status = self._check_spf(msg)
        dkim_status = self._check_dkim(msg)
        dmarc_status = self._check_dmarc(msg)

        received_headers = msg.get_all('Received', [])
        routing_analysis = self._analyze_routing(received_headers, geo_service)

        # Fallback: extract origin IP from X-Originating-IP if routing didn't find one
        if not routing_analysis.get('origin_ip'):
            x_orig_ip = msg.get('X-Originating-IP', '').strip('[]')
            if x_orig_ip and not self._is_private_ip(x_orig_ip):
                routing_analysis['origin_ip'] = x_orig_ip
                # Add as a hop
                hop = {'hop_number': 0, 'ip': x_orig_ip, 'from_host': 'X-Originating-IP', 'by_host': '', 'timestamp': '', 'suspicious': False, 'suspicious_reasons': []}
                if geo_service:
                    try:
                        geo_data = geo_service.lookup_ip(x_orig_ip)
                        hop['geo'] = {'city': geo_data.get('city'), 'country': geo_data.get('country'), 'country_code': geo_data.get('country_code'), 'org': geo_data.get('org'), 'is_hosting': geo_data.get('is_hosting'), 'risk_score': geo_data.get('risk_score')}
                    except Exception:
                        pass
                routing_analysis['hops'].insert(0, hop)

        # Fallback: resolve From domain to IP if still no origin IP
        if not routing_analysis.get('origin_ip') and from_addr and '@' in from_addr and geo_service:
            from_domain = from_addr.split('@')[-1]
            try:
                geo_result = geo_service.lookup_domain(from_domain)
                if geo_result and geo_result.get('ip'):
                    routing_analysis['origin_ip'] = geo_result['ip']
                    hop = {'hop_number': 0, 'ip': geo_result['ip'], 'from_host': from_domain, 'by_host': 'DNS-resolved', 'timestamp': '', 'suspicious': False, 'suspicious_reasons': [],
                           'geo': {'city': geo_result.get('city'), 'country': geo_result.get('country'), 'country_code': geo_result.get('country_code'), 'org': geo_result.get('org'), 'is_hosting': geo_result.get('is_hosting'), 'risk_score': geo_result.get('risk_score')}}
                    routing_analysis['hops'].insert(0, hop)
            except Exception:
                pass

        mismatches = self._detect_mismatches(from_addr, reply_to, return_path)

        analysis = {
            'from_address': from_addr,
            'reply_to': reply_to,
            'return_path': return_path,
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'x_mailer': msg.get('X-Mailer', ''),
            'x_originating_ip': msg.get('X-Originating-IP', ''),
            'authentication': {
                'spf': spf_status,
                'dkim': dkim_status,
                'dmarc': dmarc_status,
                'all_pass': spf_status == 'PASS' and dkim_status == 'PASS' and dmarc_status == 'PASS',
            },
            'routing': routing_analysis,
            'mismatches': mismatches,
            'mismatch_count': len(mismatches),
        }

        trust_score, trust_details = self._calculate_trust_score(analysis)
        analysis['trust_score'] = trust_score
        analysis['trust_level'] = self._get_trust_level(trust_score)
        analysis['trust_details'] = trust_details

        return analysis

    def _parse_email_address(self, header: str) -> str:
        if not header:
            return ''
        _, addr = parseaddr(header)
        return addr.lower()

    def _check_spf(self, msg) -> str:
        auth_results = msg.get('Authentication-Results', '')
        received_spf = msg.get('Received-SPF', '')
        combined = f"{auth_results} {received_spf}".lower()

        if 'spf=pass' in combined or 'pass spf' in combined:
            return 'PASS'
        elif 'spf=fail' in combined or 'fail spf' in combined:
            return 'FAIL'
        elif 'spf=softfail' in combined:
            return 'SOFTFAIL'
        elif 'spf=neutral' in combined:
            return 'NEUTRAL'
        elif 'spf=none' in combined:
            return 'NONE'
        return 'MISSING'

    def _check_dkim(self, msg) -> str:
        auth_results = msg.get('Authentication-Results', '').lower()
        dkim_sig = msg.get('DKIM-Signature', '')

        if 'dkim=pass' in auth_results:
            return 'PASS'
        elif 'dkim=fail' in auth_results:
            return 'FAIL'
        elif dkim_sig:
            return 'PRESENT'
        return 'MISSING'

    def _check_dmarc(self, msg) -> str:
        auth_results = msg.get('Authentication-Results', '').lower()

        if 'dmarc=pass' in auth_results:
            return 'PASS'
        elif 'dmarc=fail' in auth_results:
            return 'FAIL'
        elif 'dmarc=' in auth_results:
            return 'PRESENT'
        return 'MISSING'

    def _analyze_routing(self, received_headers: List[str], geo_service=None) -> Dict:
        """Analyze Received header chain with optional geo-enrichment per hop"""
        if not received_headers:
            return {
                'hop_count': 0,
                'hops': [],
                'origin_ip': None,
                'suspicious_hops': [],
                'suspicious': True,
            }

        hops = []
        suspicious_hops = []

        for i, header in enumerate(received_headers):
            hop_data = {
                'hop_number': i + 1,
                'raw': header[:200],
                'ip': self._extract_ip_from_received(header),
                'from_host': self._extract_host_from_received(header),
                'by_host': self._extract_by_host_from_received(header),
                'timestamp': self._extract_timestamp_from_received(header),
                'suspicious': False,
                'suspicious_reasons': [],
            }

            # Check for suspicious patterns
            header_lower = header.lower()
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in header_lower:
                    hop_data['suspicious'] = True
                    hop_data['suspicious_reasons'].append(f'Contains "{keyword}"')
                    break

            # Geo-enrich the hop IP if geo_service available
            if hop_data['ip'] and geo_service:
                try:
                    geo_data = geo_service.lookup_ip(hop_data['ip'])
                    hop_data['geo'] = {
                        'city': geo_data.get('city'),
                        'country': geo_data.get('country'),
                        'country_code': geo_data.get('country_code'),
                        'org': geo_data.get('org'),
                        'is_hosting': geo_data.get('is_hosting'),
                        'risk_score': geo_data.get('risk_score'),
                    }
                except Exception as e:
                    logger.debug(f"Geo lookup failed for hop {i}: {e}")

            if hop_data['suspicious']:
                suspicious_hops.append(hop_data)

            hops.append(hop_data)

        origin_ip = hops[0].get('ip') if hops else None

        return {
            'hop_count': len(received_headers),
            'hops': hops,
            'origin_ip': origin_ip,
            'suspicious_hops': suspicious_hops,
            'suspicious': len(suspicious_hops) > 0 or len(received_headers) > 10,
            'excessive_hops': len(received_headers) > 10,
        }

    def _extract_ip_from_received(self, header: str) -> Optional[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, header)
        for ip in matches:
            if not self._is_private_ip(ip):
                return ip
        return matches[0] if matches else None

    def _extract_host_from_received(self, header: str) -> Optional[str]:
        match = re.search(r'from\s+(\S+)', header, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_by_host_from_received(self, header: str) -> Optional[str]:
        match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_timestamp_from_received(self, header: str) -> Optional[str]:
        match = re.search(r';\s*(\w{3},\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+[\w\s+\-]+)', header)
        return match.group(1).strip() if match else None

    def _is_private_ip(self, ip: str) -> bool:
        parts = [int(p) for p in ip.split('.')]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False

    def _detect_mismatches(self, from_addr: str, reply_to: str, return_path: str) -> List[Dict]:
        mismatches = []
        from_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
        reply_domain = reply_to.split('@')[-1] if '@' in reply_to else ''
        return_domain = return_path.split('@')[-1] if '@' in return_path else ''

        if from_addr and reply_to and from_domain != reply_domain:
            mismatches.append({
                'type': 'FROM_REPLYTO_MISMATCH',
                'severity': 'HIGH',
                'detail': f'From domain ({from_domain}) != Reply-To domain ({reply_domain})',
            })

        if from_addr and return_path and from_domain != return_domain:
            mismatches.append({
                'type': 'FROM_RETURNPATH_MISMATCH',
                'severity': 'HIGH',
                'detail': f'From domain ({from_domain}) != Return-Path domain ({return_domain})',
            })

        if reply_to and return_path and reply_domain != return_domain:
            mismatches.append({
                'type': 'REPLYTO_RETURNPATH_MISMATCH',
                'severity': 'MEDIUM',
                'detail': f'Reply-To domain ({reply_domain}) != Return-Path domain ({return_domain})',
            })

        return mismatches

    def _calculate_trust_score(self, analysis: Dict) -> tuple:
        """Calculate trust score (0-100, higher = more trustworthy)"""
        score = 100
        details = {}

        # Authentication penalties
        auth = analysis.get('authentication', {})
        if auth.get('spf') != 'PASS':
            penalty = {'FAIL': 25, 'SOFTFAIL': 10, 'MISSING': 20, 'NEUTRAL': 5, 'NONE': 15}.get(auth.get('spf'), 5)
            score -= penalty
            details['spf_penalty'] = penalty

        if auth.get('dkim') != 'PASS':
            penalty = {'FAIL': 25, 'MISSING': 15, 'PRESENT': 5}.get(auth.get('dkim'), 5)
            score -= penalty
            details['dkim_penalty'] = penalty

        if auth.get('dmarc') != 'PASS':
            penalty = {'FAIL': 20, 'MISSING': 15, 'PRESENT': 5}.get(auth.get('dmarc'), 5)
            score -= penalty
            details['dmarc_penalty'] = penalty

        # Mismatch penalties
        mismatch_count = analysis.get('mismatch_count', 0)
        mismatch_penalty = mismatch_count * 15
        score -= mismatch_penalty
        details['mismatch_penalty'] = mismatch_penalty

        # Routing penalties
        routing = analysis.get('routing', {})
        if routing.get('excessive_hops'):
            score -= 10
            details['excessive_hops_penalty'] = 10

        hop_suspicious = len(routing.get('suspicious_hops', []))
        if hop_suspicious > 0:
            hop_penalty = hop_suspicious * 10
            score -= hop_penalty
            details['suspicious_hop_penalty'] = hop_penalty

        score = max(0, min(100, score))
        return score, details

    def _get_trust_level(self, score: int) -> str:
        if score >= 80:
            return 'HIGH'
        elif score >= 60:
            return 'MEDIUM'
        elif score >= 40:
            return 'LOW'
        return 'CRITICAL'
