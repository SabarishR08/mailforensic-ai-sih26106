"""
Unit tests for the Forensic Email Analyzer.

Tests parse real email header strings — no network or DB needed.
Run with: python -m pytest tests/test_forensic_analyzer.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.services.forensic_analyzer import ForensicAnalyzer


# ---------------------------------------------------------------------------
# Fixtures: sample email headers
# ---------------------------------------------------------------------------

CLEAN_EMAIL = """\
From: security@example.com
To: user@example.com
Subject: Your monthly statement
Date: Mon, 25 Aug 2025 10:30:00 +0000
Message-ID: <abc123@example.com>
Received: from mail.example.com (198.51.100.10)
        by mx.user.com; Mon, 25 Aug 2025 10:29:50 +0000
Received: from gateway.example.com (198.51.100.5)
        by mail.example.com; Mon, 25 Aug 2025 10:29:45 +0000
Authentication-Results: mx.user.com;
        spf=pass (domain of sender designates 198.51.100.10 as permitted sender);
        dkim=pass header.i=@example.com;
        dmarc=pass (p=REJECT) header.from=example.com
"""

SPF_FAIL_EMAIL = """\
From: alerts@secure-banking.tk
To: victim@gmail.com
Subject: URGENT: Verify your account NOW
Date: Mon, 25 Aug 2025 10:30:00 +0000
Message-ID: <fake123@secure-banking.tk>
Received: from localhost (127.0.0.1)
        by mx.gmail.com; Mon, 25 Aug 2025 10:29:50 +0000
Authentication-Results: mx.gmail.com;
        spf=fail (domain of secure-banking.tk does not designate 10.0.0.1 as permitted sender);
        dkim=fail header.i=@secure-banking.tk;
        dmarc=fail header.from=secure-banking.tk
Reply-To: support@different-domain.xyz
Return-Path: <bounces@yet-another-domain.com>
"""

NO_AUTH_EMAIL = """\
From: someone@unknown.com
To: user@test.com
Subject: Hello
Date: Mon, 25 Aug 2025 10:30:00 +0000
"""

SPOOFED_EMAIL = """\
From: ceo@trusted-corp.com
To: finance@victim.com
Subject: Wire Transfer Required
Date: Mon, 25 Aug 2025 10:30:00 +0000
Message-ID: <spoofed@trusted-corp.com>
Reply-To: ceo-urgent@freemail.ru
Return-Path: <bounce@freemail.ru>
Received: from suspicious-server.dynamic (45.33.32.156)
        by mx.victim.com; Mon, 25 Aug 2025 10:29:50 +0000
Authentication-Results: mx.victim.com;
        spf=fail;
        dkim=none;
        dmarc=fail
"""


class TestForensicAnalyzerSPF:
    """SPF detection tests."""

    def test_spf_pass(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(CLEAN_EMAIL)
        assert fa._check_spf(msg) == 'PASS'

    def test_spf_fail(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(SPF_FAIL_EMAIL)
        assert fa._check_spf(msg) == 'FAIL'

    def test_spf_missing(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(NO_AUTH_EMAIL)
        assert fa._check_spf(msg) == 'MISSING'

    def test_spf_softfail(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string("Authentication-Results: mx.com; spf=softfail\n")
        assert fa._check_spf(msg) == 'SOFTFAIL'

    def test_spf_neutral(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string("Authentication-Results: mx.com; spf=neutral\n")
        assert fa._check_spf(msg) == 'NEUTRAL'


class TestForensicAnalyzerDKIM:
    """DKIM detection tests."""

    def test_dkim_pass(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(CLEAN_EMAIL)
        assert fa._check_dkim(msg) == 'PASS'

    def test_dkim_fail(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(SPF_FAIL_EMAIL)
        assert fa._check_dkim(msg) == 'FAIL'

    def test_dkim_missing(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(NO_AUTH_EMAIL)
        assert fa._check_dkim(msg) == 'MISSING'

    def test_dkim_present_but_unverified(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string("DKIM-Signature: v=1; a=rsa-sha256; d=example.com;\n")
        assert fa._check_dkim(msg) == 'PRESENT'


class TestForensicAnalyzerDMARC:
    """DMARC detection tests."""

    def test_dmarc_pass(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(CLEAN_EMAIL)
        assert fa._check_dmarc(msg) == 'PASS'

    def test_dmarc_fail(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(SPF_FAIL_EMAIL)
        assert fa._check_dmarc(msg) == 'FAIL'

    def test_dmarc_missing(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(NO_AUTH_EMAIL)
        assert fa._check_dmarc(msg) == 'MISSING'


class TestForensicAnalyzerRouting:
    """Routing chain analysis tests."""

    def test_extract_ip_from_received(self):
        fa = ForensicAnalyzer()
        header = "from mail.example.com (198.51.100.10) by mx.user.com; Mon, 25 Aug 2025"
        ip = fa._extract_ip_from_received(header)
        assert ip == '198.51.100.10'

    def test_extract_ip_skips_private_prefers_public(self):
        fa = ForensicAnalyzer()
        # When both private and public IPs exist, public is returned
        header = "from localhost (127.0.0.1) via gateway (8.8.4.4) by mx.user.com"
        ip = fa._extract_ip_from_received(header)
        assert ip == '8.8.4.4'  # skips 127.0.0.1, returns public IP

    def test_extract_ip_falls_back_to_private_if_only_private(self):
        fa = ForensicAnalyzer()
        # If only private IPs exist, the first one is returned as fallback
        header = "from internal (10.0.0.5) by mx.user.com"
        ip = fa._extract_ip_from_received(header)
        assert ip == '10.0.0.5'  # fallback to only available IP

    def test_extract_ip_skips_rfc1918_with_public(self):
        fa = ForensicAnalyzer()
        header = "from lan (192.168.1.1) via (203.0.113.50) by mx.user.com"
        ip = fa._extract_ip_from_received(header)
        assert ip == '203.0.113.50'

        header3 = "from corp (172.16.0.1) via (45.33.32.10) by mx.user.com"
        ip3 = fa._extract_ip_from_received(header3)
        assert ip3 == '45.33.32.10'

    def test_extract_host_from_received(self):
        fa = ForensicAnalyzer()
        header = "from mail.example.com (198.51.100.10) by mx.user.com"
        host = fa._extract_host_from_received(header)
        assert host == 'mail.example.com'

    def test_extract_by_host_from_received(self):
        fa = ForensicAnalyzer()
        header = "from mail.example.com (198.51.100.10) by mx.user.com"
        host = fa._extract_by_host_from_received(header)
        assert host == 'mx.user.com'

    def test_analyze_routing_clean(self):
        fa = ForensicAnalyzer()
        from email import message_from_string
        msg = message_from_string(CLEAN_EMAIL)
        received = msg.get_all('Received', [])
        routing = fa._analyze_routing(received)
        assert routing['hop_count'] == 2
        assert routing['origin_ip'] is not None
        assert routing['suspicious'] is False

    def test_analyze_routing_no_received(self):
        fa = ForensicAnalyzer()
        routing = fa._analyze_routing([])
        assert routing['hop_count'] == 0
        assert routing['suspicious'] is True  # no routing is suspicious

    def test_analyze_routing_suspicious_keyword(self):
        fa = ForensicAnalyzer()
        routing = fa._analyze_routing([
            "from localhost (127.0.0.1) by mx.com; Mon, 25 Aug 2025"
        ])
        assert routing['suspicious'] is True
        assert len(routing['suspicious_hops']) > 0

    def test_analyze_routing_excessive_hops(self):
        fa = ForensicAnalyzer()
        headers = [f"from hop{i}.com (203.0.113.{i}) by next{i}.com" for i in range(15)]
        routing = fa._analyze_routing(headers)
        assert routing['excessive_hops'] is True
        assert routing['suspicious'] is True

    def test_is_private_ip(self):
        fa = ForensicAnalyzer()
        assert fa._is_private_ip('10.0.0.1') is True
        assert fa._is_private_ip('172.16.0.1') is True
        assert fa._is_private_ip('192.168.1.1') is True
        assert fa._is_private_ip('127.0.0.1') is True
        assert fa._is_private_ip('8.8.8.8') is False
        assert fa._is_private_ip('198.51.100.10') is False


class TestForensicAnalyzerMismatches:
    """Address mismatch detection tests."""

    def test_no_mismatches(self):
        fa = ForensicAnalyzer()
        mismatches = fa._detect_mismatches('user@example.com', '', '')
        assert len(mismatches) == 0

    def test_from_replyto_mismatch(self):
        fa = ForensicAnalyzer()
        mismatches = fa._detect_mismatches('user@example.com', 'user@different.com', '')
        assert len(mismatches) == 1
        assert mismatches[0]['type'] == 'FROM_REPLYTO_MISMATCH'
        assert mismatches[0]['severity'] == 'HIGH'

    def test_from_returnpath_mismatch(self):
        fa = ForensicAnalyzer()
        mismatches = fa._detect_mismatches('user@example.com', '', 'user@other.com')
        assert len(mismatches) == 1
        assert mismatches[0]['type'] == 'FROM_RETURNPATH_MISMATCH'

    def test_multiple_mismatches(self):
        fa = ForensicAnalyzer()
        mismatches = fa._detect_mismatches('a@domain1.com', 'b@domain2.com', 'c@domain3.com')
        assert len(mismatches) == 3

    def test_same_domain_no_mismatch(self):
        fa = ForensicAnalyzer()
        mismatches = fa._detect_mismatches('a@example.com', 'b@example.com', 'c@example.com')
        assert len(mismatches) == 0


class TestForensicAnalyzerTrustScore:
    """Trust score calculation tests."""

    def test_trust_score_all_pass(self):
        fa = ForensicAnalyzer()
        analysis = {
            'authentication': {'spf': 'PASS', 'dkim': 'PASS', 'dmarc': 'PASS'},
            'mismatch_count': 0,
            'routing': {'excessive_hops': False, 'suspicious_hops': []},
        }
        score, details = fa._calculate_trust_score(analysis)
        assert score == 100

    def test_trust_score_all_fail(self):
        fa = ForensicAnalyzer()
        analysis = {
            'authentication': {'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL'},
            'mismatch_count': 2,
            'routing': {'excessive_hops': True, 'suspicious_hops': [{'x': 1}]},
        }
        score, details = fa._calculate_trust_score(analysis)
        assert score == 0

    def test_trust_score_partial(self):
        fa = ForensicAnalyzer()
        analysis = {
            'authentication': {'spf': 'PASS', 'dkim': 'MISSING', 'dmarc': 'MISSING'},
            'mismatch_count': 1,
            'routing': {'excessive_hops': False, 'suspicious_hops': []},
        }
        score, details = fa._calculate_trust_score(analysis)
        assert 0 < score < 100

    def test_trust_level_labels(self):
        fa = ForensicAnalyzer()
        assert fa._get_trust_level(90) == 'HIGH'
        assert fa._get_trust_level(70) == 'MEDIUM'
        assert fa._get_trust_level(50) == 'LOW'
        assert fa._get_trust_level(20) == 'CRITICAL'


class TestForensicAnalyzerFullAnalysis:
    """End-to-end analyze() tests with complete email strings."""

    def test_clean_email_high_trust(self):
        fa = ForensicAnalyzer()
        result = fa.analyze(CLEAN_EMAIL)
        assert result['authentication']['spf'] == 'PASS'
        assert result['authentication']['dkim'] == 'PASS'
        assert result['authentication']['dmarc'] == 'PASS'
        assert result['trust_score'] >= 90
        assert result['trust_level'] == 'HIGH'
        assert result['mismatch_count'] == 0

    def test_phishing_email_low_trust(self):
        fa = ForensicAnalyzer()
        result = fa.analyze(SPF_FAIL_EMAIL)
        assert result['authentication']['spf'] == 'FAIL'
        assert result['authentication']['dkim'] == 'FAIL'
        assert result['authentication']['dmarc'] == 'FAIL'
        assert result['trust_score'] < 40
        assert result['mismatch_count'] >= 2  # From ≠ Reply-To ≠ Return-Path

    def test_spoofed_email_critical_trust(self):
        fa = ForensicAnalyzer()
        result = fa.analyze(SPOOFED_EMAIL)
        assert result['trust_score'] < 30
        assert result['trust_level'] == 'CRITICAL'
        assert result['mismatch_count'] >= 2

    def test_no_auth_headers(self):
        fa = ForensicAnalyzer()
        result = fa.analyze(NO_AUTH_EMAIL)
        assert result['authentication']['spf'] == 'MISSING'
        assert result['authentication']['dkim'] == 'MISSING'
        assert result['authentication']['dmarc'] == 'MISSING'
        assert result['trust_score'] < 60

    def test_analyze_with_geo_service_mock(self):
        """Test that geo_service integration doesn't break when provided."""
        fa = ForensicAnalyzer()

        class MockGeoService:
            def lookup_ip(self, ip):
                return {
                    'city': 'New York', 'country': 'US', 'country_code': 'US',
                    'org': 'Amazon AWS', 'is_hosting': True, 'risk_score': 40,
                }

        result = fa.analyze(CLEAN_EMAIL, geo_service=MockGeoService())
        # The geo data should appear in routing hops
        hops = result['routing']['hops']
        assert len(hops) > 0
        # At least one hop should have geo data
        geo_hops = [h for h in hops if 'geo' in h]
        assert len(geo_hops) > 0

    def test_minimal_email_text(self):
        """Even a minimal string is parsed by Python's email parser without error."""
        fa = ForensicAnalyzer()
        result = fa.analyze("Subject: hello\n")
        # email.parser is lenient — it parses this successfully
        assert result['subject'] == 'hello'
        assert result['trust_score'] >= 0

    def test_empty_string(self):
        fa = ForensicAnalyzer()
        result = fa.analyze("")
        # Empty string parses but has missing auth headers → trust score < 100
        assert result['authentication']['spf'] == 'MISSING'
        assert result['trust_score'] == 50  # 100 - 20(SPF) - 15(DKIM) - 15(DMARC)

    def test_subject_and_message_id_extracted(self):
        fa = ForensicAnalyzer()
        result = fa.analyze(CLEAN_EMAIL)
        assert result['subject'] == 'Your monthly statement'
        assert 'abc123@example.com' in result['message_id']
