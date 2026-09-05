"""Email scanning routes + live demo mode"""
import json
import asyncio
import logging
import threading
from datetime import datetime
from pathlib import Path
from flask import Blueprint, render_template, request, jsonify
from flask_socketio import join_room
from backend.services.gmail_service import fetch_recent_emails
from backend.services.sample_emails import get_sample_emails
from backend.services.email_scanner import scan_emails, scan_emails_streaming
from backend.services.ml_predictor import get_ml_predictor
from backend.extensions import socketio
from backend.models import db, EmailScanResult
from backend.spa import spa_enabled, spa_index

logger = logging.getLogger(__name__)
email_bp = Blueprint('email', __name__)

# Analysis log file
LOG_DIR = Path(__file__).parent.parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / 'analysis_log.jsonl'


def log_analysis(result, source='unknown'):
    """Append a detailed analysis log entry"""
    entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'source': source,
        'email_id': result.get('email_id', ''),
        'ml_prediction': result.get('ml', {}).get('prediction', 'unknown'),
        'ml_confidence': result.get('ml', {}).get('confidence', 0),
        'risk_score': result.get('risk_assessment', {}).get('risk_score', 0),
        'risk_level': result.get('risk_assessment', {}).get('risk_level', 'Unknown'),
        'trust_score': result.get('forensic', {}).get('trust_score', 0),
        'origin_ip': result.get('forensic', {}).get('routing', {}).get('origin_ip'),
        'x_originating_ip': result.get('forensic', {}).get('x_originating_ip'),
        'hop_count': result.get('forensic', {}).get('routing', {}).get('hop_count', 0),
        'geo_country': result.get('geo', {}).get('country_code', 'XX'),
        'geo_city': result.get('geo', {}).get('city', 'Unknown'),
        'geo_lat': result.get('geo', {}).get('latitude'),
        'geo_lon': result.get('geo', {}).get('longitude'),
        'geo_source': result.get('geo', {}).get('source', 'unknown'),
        'geo_org': result.get('geo', {}).get('org', 'Unknown'),
        'spf': result.get('forensic', {}).get('authentication', {}).get('spf', 'MISSING'),
        'dkim': result.get('forensic', {}).get('authentication', {}).get('dkim', 'MISSING'),
        'dmarc': result.get('forensic', {}).get('authentication', {}).get('dmarc', 'MISSING'),
        'mismatch_count': result.get('forensic', {}).get('mismatch_count', 0),
        'urls_checked': result.get('urls_checked', 0),
        'snippet': result.get('snippet', '')[:200],
    }
    return entry


@email_bp.route('/scan')
def email_scan_page():
    if spa_enabled():
        return spa_index()
    return render_template('email_scanner.html')


@email_bp.route('/demo')
def demo_page():
    if spa_enabled():
        return spa_index()
    return render_template('demo.html')


@email_bp.route('/api/scan/gmail', methods=['POST'])
def scan_gmail():
    limit = request.json.get('limit', 5) if request.is_json else 5
    emails = fetch_recent_emails(limit=limit)
    if not emails:
        return jsonify({'error': 'No emails fetched. Check Gmail credentials.', 'results': []}), 200

    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(scan_emails(emails, limit=limit))
    loop.close()

    # Persist results and log
    for r in results:
        risk = r.get('risk_assessment', {})
        geo = r.get('geo', {})
        scan = EmailScanResult(
            email_id=r.get('email_id', ''),
            ml_prediction=r.get('ml', {}).get('prediction', 'unknown'),
            ml_confidence=r.get('ml', {}).get('confidence', 0),
            risk_score=risk.get('risk_score', 0),
            risk_level=risk.get('risk_level', 'Unknown'),
            forensic_trust_score=r.get('forensic', {}).get('trust_score', 0),
            geo_country=geo.get('country_code', ''),
            origin_ip=r.get('forensic', {}).get('routing', {}).get('origin_ip', ''),
            full_result=json.dumps(r, default=str),
        )
        db.session.add(scan)
        log_analysis(r, source='gmail')
    db.session.commit()

    return jsonify({'count': len(results), 'results': results, 'source': 'gmail'})


@email_bp.route('/api/scan/sample', methods=['POST'])
def scan_sample():
    """Scan sample/demo emails - no Gmail auth required"""
    limit = request.json.get('limit', 5) if request.is_json else 5
    emails = get_sample_emails(limit=limit)
    
    if not emails:
        return jsonify({'error': 'No sample emails available', 'results': []}), 200

    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(scan_emails(emails, limit=limit))
    loop.close()

    # Persist results and log
    for r in results:
        risk = r.get('risk_assessment', {})
        geo = r.get('geo', {})
        scan = EmailScanResult(
            email_id=r.get('email_id', ''),
            ml_prediction=r.get('ml', {}).get('prediction', 'unknown'),
            ml_confidence=r.get('ml', {}).get('confidence', 0),
            risk_score=risk.get('risk_score', 0),
            risk_level=risk.get('risk_level', 'Unknown'),
            forensic_trust_score=r.get('forensic', {}).get('trust_score', 0),
            geo_country=geo.get('country_code', ''),
            origin_ip=r.get('forensic', {}).get('routing', {}).get('origin_ip', ''),
            full_result=json.dumps(r, default=str),
        )
        db.session.add(scan)
        log_analysis(r, source='sample')
    db.session.commit()

    return jsonify({'count': len(results), 'results': results, 'source': 'sample'})


@email_bp.route('/api/scan/text', methods=['POST'])
def scan_text():
    email_text = request.json.get('text', '') if request.is_json else ''
    if not email_text:
        return jsonify({'error': 'No email text provided'}), 400

    predictor = get_ml_predictor()
    prediction, confidence = predictor.predict_email(email_text) if predictor.is_email_model_loaded() else ('unknown', 0.5)

    return jsonify({
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'model_loaded': predictor.is_email_model_loaded(),
    })


@email_bp.route('/api/logs')
def get_logs():
    """Return recent analysis logs from SQLite DB"""
    limit = request.args.get('limit', 50, type=int)
    scans = EmailScanResult.query.order_by(EmailScanResult.timestamp.desc()).limit(limit).all()
    logs = []
    for s in scans:
        full = json.loads(s.full_result) if s.full_result else {}
        geo = full.get('geo', {})
        logs.append({
            'id': s.id,
            'timestamp': s.timestamp.isoformat() if s.timestamp else None,
            'email_id': s.email_id,
            'ml_prediction': s.ml_prediction,
            'ml_confidence': s.ml_confidence,
            'risk_score': s.risk_score,
            'risk_level': s.risk_level,
            'trust_score': s.forensic_trust_score,
            'geo_country': geo.get('country_code', s.geo_country or ''),
            'geo_city': geo.get('city', ''),
            'origin_ip': s.origin_ip or '',
            'source': 'gmail' if not s.email_id.startswith('sample_') else 'sample',
        })
    return jsonify({'logs': logs, 'count': len(logs)})


@email_bp.route('/api/scan/backfill', methods=['POST'])
def backfill_geo():
    """Re-geolocate all scans with bad geo data"""
    from backend.services.geo_service import get_geo_service
    geo_service = get_geo_service()
    
    scans = EmailScanResult.query.filter(
        (EmailScanResult.geo_country == 'XX') | (EmailScanResult.geo_country == '') | (EmailScanResult.geo_country.is_(None))
    ).all()
    
    updated = 0
    for s in scans:
        if not s.origin_ip or s.origin_ip.startswith('10.') or s.origin_ip.startswith('192.168.'):
            continue
        try:
            geo_data = geo_service.lookup_ip(s.origin_ip)
            if geo_data and geo_data.get('country_code') != 'XX':
                s.geo_country = geo_data.get('country_code', 'XX')
                if s.full_result:
                    full = json.loads(s.full_result)
                    full['geo'] = geo_data
                    s.full_result = json.dumps(full, default=str)
                updated += 1
        except Exception:
            pass
    
    db.session.commit()
    return jsonify({'updated': updated, 'total_checked': len(scans)})


# --- SocketIO Demo Events ---

@socketio.on('connect')
def handle_connect():
    pass  # Client connected


@socketio.on('join_demo')
def handle_join_demo():
    join_room('demo')
    socketio.emit('connected', {'message': 'Connected to live scan server'}, room='demo')


@socketio.on('start_demo_scan')
def handle_demo_scan(data):
    """Handle demo scan request via SocketIO"""
    limit = data.get('limit', 5)
    use_sample = data.get('use_sample', False)  # New parameter

    def run_scan():
        if use_sample:
            emails = get_sample_emails(limit=limit)
            source = 'sample'
        else:
            emails = fetch_recent_emails(limit=limit)
            source = 'gmail'
        
        if not emails:
            socketio.emit('scan_error', {
                'message': 'No emails fetched. Check Gmail credentials or use sample data.',
                'error': 'No emails'
            }, room='demo')
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            scan_emails_streaming(emails, limit=limit, socketio_instance=socketio, room='demo')
        )
        loop.close()

        # Persist results
        with db.engine.connect() as conn:
            for r in results:
                risk = r.get('risk_assessment', {})
                geo = r.get('geo', {})
                scan = EmailScanResult(
                    email_id=r.get('email_id', ''),
                    ml_prediction=r.get('ml', {}).get('prediction', 'unknown'),
                    ml_confidence=r.get('ml', {}).get('confidence', 0),
                    risk_score=risk.get('risk_score', 0),
                    risk_level=risk.get('risk_level', 'Unknown'),
                    forensic_trust_score=r.get('forensic', {}).get('trust_score', 0),
                    geo_country=geo.get('country_code', ''),
                    origin_ip=r.get('forensic', {}).get('routing', {}).get('origin_ip', ''),
                    full_result=json.dumps(r, default=str),
                )
                db.session.add(scan)
            db.session.commit()

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
