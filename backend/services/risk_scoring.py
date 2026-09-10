"""
Unified Risk Scoring Engine for MailForensic
Combines ML prediction, threat intelligence, URL intelligence & QRishing,
geolocation, header forensics, and content NLP into a composite 0-100 risk score.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculate composite risk scores from all analysis signals"""

    WEIGHTS = {
        'ml_prediction': 0.20,
        'threat_intel': 0.20,
        'url_intelligence': 0.15,
        'authentication': 0.15,
        'geolocation': 0.15,
        'forensic': 0.08,
        'content': 0.07,
    }

    @classmethod
    def calculate(cls, analysis: Dict) -> Dict:
        """
        Calculate composite risk score from all analysis signals.
        Input should contain: ml_result, threat_intel, url_intelligence, qr_analysis, geo_data, forensic, content_analysis
        Returns: { 'risk_score': 0-100, 'risk_level': str, 'breakdown': dict, 'weights': dict }
        """
        breakdown = {}

        # 1. ML Prediction contribution (0-100)
        ml = analysis.get('ml_result', {})
        if ml.get('prediction') == 'phishing':
            ml_score = ml.get('confidence', 0.5) * 100
        elif ml.get('prediction') == 'suspicious':
            ml_score = 50
        elif ml.get('prediction') == 'legitimate':
            ml_score = (1 - ml.get('confidence', 0.5)) * 100
        else:
            ml_score = 50
        breakdown['ml_prediction'] = ml_score

        # 2. Threat Intel contribution (0-100)
        ti = analysis.get('threat_intel', {})
        ti_score = ti.get('threat_score', 0)
        breakdown['threat_intel'] = min(100, max(0, ti_score))

        # 3. URL Intelligence & QRishing contribution (0-100)
        url_intel = analysis.get('url_intelligence', {})
        url_score = url_intel.get('max_risk_score', url_intel.get('risk_score', 0))
        
        # QRishing threat boost if QR code leads to suspicious URL/payload
        qr_analysis = analysis.get('qr_analysis', {})
        if qr_analysis.get('qrishing_threat'):
            url_score = max(url_score, 75)
        elif qr_analysis.get('qr_detected'):
            url_score = max(url_score, 30)

        breakdown['url_intelligence'] = min(100, max(0, url_score))

        # 4. Authentication (SPF/DKIM/DMARC) contribution
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

        # 5. Geolocation contribution
        geo = analysis.get('geo_data', {})
        geo_score = geo.get('risk_score', 20)
        breakdown['geolocation'] = min(100, max(0, geo_score))

        # 6. Forensic header analysis (trust score inverted)
        trust_score = forensic.get('trust_score', 50)
        forensic_risk = 100 - trust_score
        breakdown['forensic'] = min(100, max(0, forensic_risk))

        # 7. Content NLP analysis
        content = analysis.get('content_analysis', {})
        nlp = content.get('nlp_result', {})
        cat = nlp.get('category', '')
        if cat == 'Phishing':
            content_score = 80
        elif cat == 'Spam':
            content_score = 50
        elif cat == 'Suspicious':
            content_score = 60
        else:
            content_score = 10
        breakdown['content'] = content_score

        # Weighted composite calculation
        total = sum(breakdown[k] * cls.WEIGHTS[k] for k in cls.WEIGHTS)
        risk_score = min(100, max(0, int(round(total))))

        # Calibrate risk score and level to ensure consistency with ML prediction and threats
        ml_pred = ml.get('prediction', '').lower()
        if ml_pred == 'phishing':
            # A confirmed phishing payload must have at least Medium/High severity, never Low or Safe
            risk_score = max(risk_score, 55)

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
