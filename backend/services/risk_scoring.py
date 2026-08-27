"""
Unified Risk Scoring Engine
Combines ML prediction, threat intelligence, geolocation, and forensic analysis
into a single 0-100 risk score.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculate unified risk scores from multiple analysis signals"""

    WEIGHTS = {
        'ml_prediction': 0.25,
        'threat_intel': 0.25,
        'authentication': 0.15,
        'geolocation': 0.15,
        'forensic': 0.10,
        'content': 0.10,
    }

    @classmethod
    def calculate(cls, analysis: Dict) -> Dict:
        """
        Calculate composite risk score from all analysis signals.
        Input should contain: ml_result, threat_intel, geo_data, forensic, content_analysis
        Returns: { 'risk_score': 0-100, 'risk_level': str, 'breakdown': dict }
        """
        breakdown = {}

        # ML Prediction contribution (0-100)
        ml = analysis.get('ml_result', {})
        if ml.get('prediction') == 'phishing':
            ml_score = ml.get('confidence', 0.5) * 100
        elif ml.get('prediction') == 'suspicious':
            ml_score = 50  # Suspicious = moderate risk, not confirmed phishing
        elif ml.get('prediction') == 'legitimate':
            ml_score = (1 - ml.get('confidence', 0.5)) * 100
        else:
            ml_score = 50  # unknown = neutral
        breakdown['ml_prediction'] = ml_score

        # Threat Intel contribution (0-100)
        ti = analysis.get('threat_intel', {})
        ti_score = ti.get('threat_score', 0)
        breakdown['threat_intel'] = ti_score

        # Authentication (SPF/DKIM/DMARC) contribution
        forensic = analysis.get('forensic', {})
        auth = forensic.get('authentication', {})
        auth_score = 0
        if auth.get('spf') != 'PASS':
            auth_score += 33
        if auth.get('dkim') != 'PASS':
            auth_score += 33
        if auth.get('dmarc') != 'PASS':
            auth_score += 34
        breakdown['authentication'] = min(100, auth_score)

        # Geolocation contribution
        geo = analysis.get('geo_data', {})
        geo_score = geo.get('risk_score', 20)
        breakdown['geolocation'] = geo_score

        # Forensic (trust score is inverted — high trust = low risk)
        trust_score = forensic.get('trust_score', 50)
        forensic_risk = 100 - trust_score
        breakdown['forensic'] = forensic_risk

        # Content analysis (from Gemini NLP or keyword matching)
        content = analysis.get('content_analysis', {})
        nlp = content.get('nlp_result', {})
        if nlp.get('category') == 'Phishing':
            content_score = 80
        elif nlp.get('category') == 'Spam':
            content_score = 50
        elif nlp.get('category') == 'Suspicious':
            content_score = 60
        else:
            content_score = 10
        breakdown['content'] = content_score

        # Weighted composite
        total = sum(breakdown[k] * cls.WEIGHTS[k] for k in cls.WEIGHTS)
        risk_score = min(100, max(0, int(total)))

        if risk_score >= 70:
            risk_level = 'Critical'
        elif risk_score >= 50:
            risk_level = 'High'
        elif risk_score >= 30:
            risk_level = 'Medium'
        elif risk_score >= 15:
            risk_level = 'Low'
        else:
            risk_level = 'Safe'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'breakdown': breakdown,
            'weights': cls.WEIGHTS,
        }
