"""
Unified Email Scanner
Orchestrates: ML prediction → QRishing Extraction → URL Intelligence → Threat Intel → Geo Enrichment → Forensic Analysis → Risk Score
"""

import asyncio
import logging
import nest_asyncio
from datetime import datetime
from typing import Dict, List

from backend.services.ml_predictor import get_ml_predictor
from backend.services.threat_intelligence import unified_url_check
from backend.services.url_intelligence import URLAnalyzer
from backend.services.qr_service import QREmailAnalyzer
from backend.services.geo_service import get_geo_service
from backend.services.forensic_analyzer import ForensicAnalyzer
from backend.services.risk_scoring import RiskScoringEngine
from backend.services.gemini_service import classify_email_nlp
from backend.utils.url_utils import extract_urls

nest_asyncio.apply()
logger = logging.getLogger(__name__)

SNIPPET_LENGTH = 250


async def scan_single_email(email_data: dict, index: int) -> dict:
    """
    Full pipeline scan of a single email.
    email_data contains: 'body', optionally 'raw_body', 'raw_headers', 'attachments'.
    """
    body = email_data.get('body', '')
    raw_body = email_data.get('raw_body', '')
    raw_headers = email_data.get('raw_headers', '')
    email_id = email_data.get('id', f'email_{index}')

    ml_predictor = get_ml_predictor()
    geo_service = get_geo_service()
    forensic = ForensicAnalyzer()

    # 1. ML Prediction
    ml_prediction, ml_confidence = ml_predictor.predict_email(body) if ml_predictor.is_email_model_loaded() else ('unknown', 0.5)

    # 2. Extract embedded/attached QR codes & QRishing payloads
    qr_analysis = QREmailAnalyzer.extract_qr_from_email(email_data)

    # 3. Extract URLs from body, headers, and QR payloads
    body_urls = extract_urls(body + ' ' + raw_body)
    header_urls = extract_urls(raw_headers) if raw_headers else []
    qr_urls = qr_analysis.get('urls_found', [])
    
    all_urls = list(dict.fromkeys(body_urls + header_urls + qr_urls))

    # 4. Run URL Intelligence and Threat Intel on all extracted URLs
    url_intel_results = {}
    threat_intel_results = {}
    max_url_intel_score = 0
    max_ti_score = 0
    url_threats_list = []

    for url in all_urls[:10]:
        try:
            # Heavy URL intelligence heuristic analysis
            intel = URLAnalyzer.full_analysis(url, check_redirects=False)
            url_intel_results[url] = intel
            if intel.get('risk_score', 0) > max_url_intel_score:
                max_url_intel_score = intel.get('risk_score', 0)
            if intel.get('threats'):
                url_threats_list.extend(intel['threats'])
        except Exception as e:
            logger.error(f"URL intelligence error for {url}: {e}")

    if all_urls:
        try:
            # Threat intel lookup (VT, SafeBrowsing, RDAP) for top URLs
            tasks = [unified_url_check(url) for url in all_urls[:5]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for url, result in zip(all_urls[:5], results):
                if not isinstance(result, Exception):
                    threat_intel_results[url] = result
        except Exception as e:
            logger.error(f"Threat intel error: {e}")

    max_ti_score = max((r.get('threat_score', 0) for r in threat_intel_results.values()), default=0)

    url_intelligence_summary = {
        'total_urls': len(all_urls),
        'max_risk_score': max_url_intel_score,
        'url_threats': list(dict.fromkeys(url_threats_list)),
        'details': url_intel_results,
    }

    # 5. NLP Classification (Gemini)
    nlp_result = await classify_email_nlp(body)

    # 6. Forensic Analysis (if headers available, or synthesize from available content)
    forensic_result = {}
    content_for_forensic = raw_headers if raw_headers else (raw_body or body)
    if content_for_forensic:
        forensic_result = forensic.analyze(content_for_forensic, geo_service=geo_service)

    # 7. Geo enrichment of sender IP
    origin_ip = forensic_result.get('routing', {}).get('origin_ip')
    geo_data = {}
    if origin_ip:
        geo_data = geo_service.lookup_ip(origin_ip)

    # 8. Calculate unified composite risk score
    risk_assessment = RiskScoringEngine.calculate({
        'ml_result': {'prediction': ml_prediction, 'confidence': ml_confidence},
        'threat_intel': {'threat_score': max_ti_score},
        'url_intelligence': url_intelligence_summary,
        'qr_analysis': qr_analysis,
        'forensic': forensic_result,
        'geo_data': geo_data,
        'content_analysis': {'nlp_result': nlp_result},
    })

    return {
        'email_id': email_id,
        'index': index,
        'snippet': body[:SNIPPET_LENGTH],
        'ml': {'prediction': ml_prediction, 'confidence': round(ml_confidence, 4)},
        'urls_checked': len(all_urls),
        'urls_found': all_urls,
        'url_intelligence': url_intelligence_summary,
        'url_results': threat_intel_results,
        'qr_analysis': qr_analysis,
        'nlp': nlp_result,
        'forensic': forensic_result,
        'chain_of_custody': forensic_result.get('chain_of_custody', {}),
        'geo': geo_data,
        'risk_assessment': risk_assessment,
        'timestamp': datetime.now().isoformat(),
    }


async def scan_emails(emails: List[dict], limit: int = 10) -> List[dict]:
    """Scan multiple emails concurrently"""
    results = []
    for i, email_data in enumerate(emails[:limit]):
        try:
            result = await scan_single_email(email_data, i)
            results.append(result)
        except Exception as e:
            logger.error(f"Scan error for email {i}: {e}")
            results.append({
                'email_id': email_data.get('id', f'email_{i}'),
                'index': i, 'error': str(e),
                'risk_assessment': {'risk_score': 0, 'risk_level': 'Error'}
            })
    return results


async def scan_emails_streaming(emails: List[dict], limit: int = 10, socketio_instance=None, room: str = None) -> List[dict]:
    """
    Scan emails with real-time SocketIO progress events.
    """
    total = min(len(emails), limit)
    results = []

    if socketio_instance and room:
        socketio_instance.emit('scan_started', {
            'total': total,
            'message': f'Starting scan of {total} emails...'
        }, room=room)

    for i, email_data in enumerate(emails[:limit]):
        email_id = email_data.get('id', f'email_{i}')
        body_preview = email_data.get('body', '')[:SNIPPET_LENGTH]

        if socketio_instance and room:
            socketio_instance.emit('scan_progress', {
                'current': i + 1,
                'total': total,
                'email_id': email_id,
                'status': 'scanning',
                'message': f'Analyzing email {i+1}/{total}: {email_id}'
            }, room=room)

        try:
            result = await scan_single_email(email_data, i)
            results.append(result)

            if socketio_instance and room:
                socketio_instance.emit('scan_result', {
                    'email_id': email_id,
                    'index': i,
                    'total': total,
                    'snippet': body_preview,
                    'ml': result.get('ml', {}),
                    'nlp': result.get('nlp', {}),
                    'forensic': result.get('forensic', {}),
                    'geo': result.get('geo', {}),
                    'url_intelligence': result.get('url_intelligence', {}),
                    'qr_analysis': result.get('qr_analysis', {}),
                    'risk_assessment': result.get('risk_assessment', {}),
                    'urls_checked': result.get('urls_checked', 0),
                    'status': 'complete',
                    'message': f'Email {i+1}/{total} complete: {result.get("ml", {}).get("prediction", "?")} '
                               f'(risk: {result.get("risk_assessment", {}).get("risk_level", "?")})'
                }, room=room)

        except Exception as e:
            logger.error(f"Scan error for email {i}: {e}")
            error_result = {
                'email_id': email_id,
                'index': i, 'error': str(e),
                'risk_assessment': {'risk_score': 0, 'risk_level': 'Error'}
            }
            results.append(error_result)

            if socketio_instance and room:
                socketio_instance.emit('scan_error', {
                    'email_id': email_id,
                    'index': i,
                    'total': total,
                    'error': str(e),
                    'message': f'Error scanning email {i+1}/{total}'
                }, room=room)

    if socketio_instance and room:
        phishing_count = sum(1 for r in results if r.get('ml', {}).get('prediction') == 'phishing')
        socketio_instance.emit('scan_complete', {
            'total': total,
            'results_count': len(results),
            'phishing_detected': phishing_count,
            'message': f'Scan complete. {phishing_count}/{total} emails flagged as phishing.'
        }, room=room)

    return results
