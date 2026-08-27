"""Email scanning routes + live demo mode"""
import json
import asyncio
import threading
from flask import Blueprint, render_template, request, jsonify
from flask_socketio import join_room
from backend.services.gmail_service import fetch_recent_emails
from backend.services.email_scanner import scan_emails, scan_emails_streaming
from backend.services.ml_predictor import get_ml_predictor
from backend.extensions import socketio
from backend.models import db, EmailScanResult

email_bp = Blueprint('email', __name__)


@email_bp.route('/scan')
def email_scan_page():
    return render_template('email_scanner.html')


@email_bp.route('/demo')
def demo_page():
    return render_template('demo.html')


@email_bp.route('/api/scan/gmail', methods=['POST'])
def scan_gmail():
    limit = request.json.get('limit', 5) if request.is_json else 5
    emails = fetch_recent_emails(limit=limit)
    if not emails:
        return jsonify({'error': 'No emails fetched', 'results': []}), 200

    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(scan_emails(emails, limit=limit))
    loop.close()

    # Persist results
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

    return jsonify({'count': len(results), 'results': results})


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

    def run_scan():
        emails = fetch_recent_emails(limit=limit)
        if not emails:
            socketio.emit('scan_error', {
                'message': 'No emails fetched. Check Gmail credentials.',
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
