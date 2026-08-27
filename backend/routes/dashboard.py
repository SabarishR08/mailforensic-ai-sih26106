"""Dashboard routes"""
from flask import Blueprint, render_template
from backend.models import ThreatLog, EmailScanResult

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
def dashboard():
    recent_threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(20).all()
    recent_scans = EmailScanResult.query.order_by(EmailScanResult.timestamp.desc()).limit(20).all()
    stats = {
        'total_scans': EmailScanResult.query.count(),
        'phishing_detected': EmailScanResult.query.filter_by(ml_prediction='phishing').count(),
        'total_threats': ThreatLog.query.filter(ThreatLog.severity.in_(['High', 'Critical'])).count(),
    }
    return render_template('dashboard.html', threats=recent_threats, scans=recent_scans, stats=stats)


@dashboard_bp.route('/dashboard/threat-intel')
def threat_intel():
    """Threat Intelligence dashboard with aggregated trends and charts"""
    return render_template('threat_intel.html')
