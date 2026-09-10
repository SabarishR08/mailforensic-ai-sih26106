"""
Forensic PDF Report Generator
Generates per-email forensic breakdown reports using ReportLab.
Updated with URL Intelligence & QRishing Threat Breakdown.
"""

import os
import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger(__name__)


class ForensicReportGenerator:
    """Generate forensic PDF reports for email analysis"""

    @staticmethod
    def generate_report(analysis: Dict, filename: str = None) -> str:
        """
        Generate a PDF forensic report from analysis data.
        Returns the path to the generated PDF file.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

        output_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'uploads', 'reports')
        os.makedirs(output_dir, exist_ok=True)

        if not filename:
            filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=A4,
                                rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, spaceAfter=20,
                                     textColor=colors.HexColor('#1a237e'))
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, spaceAfter=10,
                                       textColor=colors.HexColor('#283593'))
        body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=10, spaceAfter=6)

        # --- Title ---
        elements.append(Paragraph("Email Forensic Analysis Report", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#283593')))
        elements.append(Spacer(1, 15))

        # --- Risk Summary ---
        risk = analysis.get('risk_assessment', {})
        risk_score = risk.get('risk_score', 'N/A')
        risk_level = risk.get('risk_level', 'Unknown')
        risk_color = {'Critical': '#d32f2f', 'High': '#f57c00', 'Medium': '#fbc02d', 'Low': '#388e3c', 'Safe': '#1976d2'}.get(risk_level, '#757575')

        elements.append(Paragraph("Risk Assessment", heading_style))
        risk_data = [
            ['Risk Score', f'{risk_score}/100'],
            ['Risk Level', risk_level],
            ['Trust Score', f"{analysis.get('forensic', {}).get('trust_score', 'N/A')}/100"],
            ['Trust Level', analysis.get('forensic', {}).get('trust_level', 'Unknown')],
        ]
        risk_table = Table(risk_data, colWidths=[2*inch, 4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eaf6')),
            ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor(risk_color)),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 15))

        # --- QR Code / QRishing Analysis ---
        qr = analysis.get('qr_analysis', {})
        if qr.get('qr_detected'):
            elements.append(Paragraph("QR Code / QRishing Analysis", heading_style))
            qr_status = "CRITICAL (QRishing Threat Detected)" if qr.get('qrishing_threat') else "Detected (Clean Payload)"
            qr_color = "#d32f2f" if qr.get('qrishing_threat') else "#388e3c"
            
            payload_str = ", ".join(qr.get('payloads', []))[:100] or "None"
            qr_data = [
                ['QR Status', qr_status],
                ['QR Count', str(qr.get('qr_count', 0))],
                ['Decoded Payload', payload_str],
            ]
            qr_table = Table(qr_data, colWidths=[2*inch, 4*inch])
            qr_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ffebee')),
                ('TEXTCOLOR', (1, 0), (1, 0), colors.HexColor(qr_color)),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(qr_table)
            elements.append(Spacer(1, 15))

        # --- URL Intelligence Analysis ---
        url_intel = analysis.get('url_intelligence', {})
        if url_intel and url_intel.get('total_urls', 0) > 0:
            elements.append(Paragraph("URL Intelligence Breakdown", heading_style))
            url_threats = url_intel.get('url_threats', [])
            threats_str = ", ".join(url_threats) if url_threats else "None detected"
            
            url_data = [
                ['Total URLs Extracted', str(url_intel.get('total_urls', 0))],
                ['Max URL Risk Score', f"{url_intel.get('max_risk_score', 0)}/100"],
                ['Detected Threats', threats_str[:120]],
            ]
            url_table = Table(url_data, colWidths=[2*inch, 4*inch])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eaf6')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(url_table)
            elements.append(Spacer(1, 15))

        # --- Email Headers ---
        forensic = analysis.get('forensic', {})
        elements.append(Paragraph("Email Headers", heading_style))
        header_data = [
            ['From', forensic.get('from_address', analysis.get('from', 'N/A'))],
            ['Reply-To', forensic.get('reply_to', 'N/A')],
            ['Return-Path', forensic.get('return_path', 'N/A')],
            ['Subject', forensic.get('subject', analysis.get('subject', 'N/A'))],
            ['Date', forensic.get('date', analysis.get('date', 'N/A'))],
            ['Message-ID', str(forensic.get('message_id', analysis.get('email_id', 'N/A')))[:60]],
            ['X-Mailer', forensic.get('x_mailer', 'N/A')],
        ]
        header_table = Table(header_data, colWidths=[1.5*inch, 4.5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eaf6')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 15))

        # --- Authentication ---
        auth = forensic.get('authentication', {})
        elements.append(Paragraph("Authentication Analysis", heading_style))
        auth_data = [
            ['Check', 'Status', 'Result'],
            ['SPF', auth.get('spf', 'N/A'), '✓ PASS' if auth.get('spf') == 'PASS' else '✗ FAIL'],
            ['DKIM', auth.get('dkim', 'N/A'), '✓ PASS' if auth.get('dkim') == 'PASS' else '✗ FAIL'],
            ['DMARC', auth.get('dmarc', 'N/A'), '✓ PASS' if auth.get('dmarc') == 'PASS' else '✗ FAIL'],
        ]
        auth_table = Table(auth_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283593')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
        ]))
        elements.append(auth_table)
        elements.append(Spacer(1, 15))

        # --- Risk Breakdown ---
        breakdown = risk.get('breakdown', {})
        if breakdown:
            elements.append(Paragraph("Risk Score Breakdown", heading_style))
            bd_data = [['Component', 'Score', 'Weight']]
            weights = risk.get('weights', {})
            for k, v in breakdown.items():
                bd_data.append([k.replace('_', ' ').title(), f"{v:.1f}", f"{weights.get(k, 0)*100:.0f}%"])
            bd_table = Table(bd_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
            bd_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283593')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(bd_table)

        # Build PDF
        doc.build(elements)
        logger.info(f"Forensic report generated: {filepath}")
        return filepath
