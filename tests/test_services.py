"""
Unit tests for RiskScoringEngine and URL utilities.

Run with: python -m pytest tests/test_services.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.services.risk_scoring import RiskScoringEngine
from backend.utils.url_utils import extract_urls


# ---------------------------------------------------------------------------
# RiskScoringEngine Tests
# ---------------------------------------------------------------------------

class TestRiskScoringEngine:
    """Tests for the unified risk scoring calculation."""

    def test_all_clear_low_risk(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'legitimate', 'confidence': 0.95},
            'threat_intel': {'threat_score': 5},
            'forensic': {'trust_score': 95, 'authentication': {'spf': 'PASS', 'dkim': 'PASS', 'dmarc': 'PASS'}},
            'geo_data': {'risk_score': 5},
            'content_analysis': {'nlp_result': {'category': 'Legitimate'}},
        })
        assert result['risk_score'] < 25
        assert result['risk_level'] in ('Safe', 'Low')

    def test_high_risk_phishing(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'phishing', 'confidence': 0.98},
            'threat_intel': {'threat_score': 95},
            'forensic': {'trust_score': 10, 'authentication': {'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL'}},
            'geo_data': {'risk_score': 80},
            'content_analysis': {'nlp_result': {'category': 'Phishing'}},
        })
        assert result['risk_score'] >= 70
        assert result['risk_level'] in ('Critical', 'High')

    def test_unknown_ml_prediction(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'unknown', 'confidence': 0.5},
            'threat_intel': {'threat_score': 0},
            'forensic': {'trust_score': 50, 'authentication': {}},
            'geo_data': {'risk_score': 0},
            'content_analysis': {'nlp_result': {}},
        })
        # Unknown ML should give neutral 50 score
        breakdown = result['breakdown']
        assert breakdown['ml_prediction'] == 50

    def test_empty_input(self):
        result = RiskScoringEngine.calculate({})
        assert 0 <= result['risk_score'] <= 100
        assert result['risk_level'] in ('Safe', 'Low', 'Medium', 'High', 'Critical')

    def test_risk_levels_boundaries(self):
        # Force risk_score = 70 → Critical
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'phishing', 'confidence': 1.0},
            'threat_intel': {'threat_score': 100},
            'forensic': {'trust_score': 0, 'authentication': {'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL'}},
            'geo_data': {'risk_score': 100},
            'content_analysis': {'nlp_result': {'category': 'Phishing'}},
        })
        assert result['risk_score'] >= 70
        assert result['risk_level'] == 'Critical'

    def test_score_clamped_to_100(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'phishing', 'confidence': 1.0},
            'threat_intel': {'threat_score': 100},
            'forensic': {'trust_score': 0, 'authentication': {'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL'}},
            'geo_data': {'risk_score': 100},
            'content_analysis': {'nlp_result': {'category': 'Phishing'}},
        })
        assert result['risk_score'] <= 100

    def test_score_clamped_to_0(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'legitimate', 'confidence': 1.0},
            'threat_intel': {'threat_score': 0},
            'forensic': {'trust_score': 100, 'authentication': {'spf': 'PASS', 'dkim': 'PASS', 'dmarc': 'PASS'}},
            'geo_data': {'risk_score': 0},
            'content_analysis': {'nlp_result': {'category': 'Legitimate'}},
        })
        assert result['risk_score'] >= 0

    def test_weights_present(self):
        result = RiskScoringEngine.calculate({})
        assert 'weights' in result
        assert len(result['weights']) == 6
        assert abs(sum(result['weights'].values()) - 1.0) < 0.01

    def test_breakdown_keys(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'phishing', 'confidence': 0.8},
            'threat_intel': {'threat_score': 50},
            'forensic': {'trust_score': 40, 'authentication': {'spf': 'FAIL', 'dkim': 'PASS', 'dmarc': 'MISSING'}},
            'geo_data': {'risk_score': 30},
            'content_analysis': {'nlp_result': {'category': 'Suspicious'}},
        })
        breakdown = result['breakdown']
        expected_keys = {'ml_prediction', 'threat_intel', 'authentication', 'geolocation', 'forensic', 'content'}
        assert set(breakdown.keys()) == expected_keys

    def test_auth_fail_increases_score(self):
        base = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'unknown', 'confidence': 0.5},
            'threat_intel': {'threat_score': 0},
            'forensic': {'trust_score': 50, 'authentication': {'spf': 'PASS', 'dkim': 'PASS', 'dmarc': 'PASS'}},
            'geo_data': {'risk_score': 0},
            'content_analysis': {'nlp_result': {}},
        })
        no_auth = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'unknown', 'confidence': 0.5},
            'threat_intel': {'threat_score': 0},
            'forensic': {'trust_score': 50, 'authentication': {'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL'}},
            'geo_data': {'risk_score': 0},
            'content_analysis': {'nlp_result': {}},
        })
        assert no_auth['risk_score'] > base['risk_score']

    def test_spam_content_category(self):
        result = RiskScoringEngine.calculate({
            'ml_result': {'prediction': 'unknown'},
            'threat_intel': {'threat_score': 0},
            'forensic': {'trust_score': 50, 'authentication': {}},
            'geo_data': {'risk_score': 0},
            'content_analysis': {'nlp_result': {'category': 'Spam'}},
        })
        assert result['breakdown']['content'] == 50


# ---------------------------------------------------------------------------
# URL Utilities Tests
# ---------------------------------------------------------------------------

class TestExtractUrls:
    """Tests for URL extraction from text."""

    def test_single_url(self):
        urls = extract_urls("Visit https://google.com for info")
        assert urls == ['https://google.com']

    def test_multiple_urls(self):
        text = "Check https://google.com and http://example.org/path"
        urls = extract_urls(text)
        assert len(urls) == 2
        assert 'https://google.com' in urls
        assert 'http://example.org/path' in urls

    def test_www_prefix(self):
        urls = extract_urls("Go to www.example.com now")
        assert len(urls) == 1
        assert urls[0].startswith('https://')

    def test_no_urls(self):
        urls = extract_urls("No links here, just plain text")
        assert urls == []

    def test_deduplication(self):
        text = "https://google.com and again https://google.com"
        urls = extract_urls(text)
        assert len(urls) == 1

    def test_url_with_query_params(self):
        text = "https://example.com/search?q=test&page=1"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert 'q=test' in urls[0]

    def test_url_with_port(self):
        text = "https://example.com:8080/api"
        urls = extract_urls(text)
        assert len(urls) == 1

    def test_complex_text(self):
        text = """Hey, check these out:
        https://legit-site.com/page1
        Also http://another.org/path/to/resource?q=hello&lang=en
        And www.simple.com
        No more links after this."""
        urls = extract_urls(text)
        assert len(urls) == 3

    def test_empty_string(self):
        urls = extract_urls("")
        assert urls == []
