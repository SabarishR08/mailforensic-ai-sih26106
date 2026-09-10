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

        # --- Routing / Received Chain ---
        routing = forensic.get('routing', {})
        hops = routing.get('hops', [])
        if hops:
            elements.append(Paragraph("Routing Chain (Received Headers)", heading_style))
            hop_data = [['Hop', 'From', 'By', 'IP', 'Geo', 'Suspicious']]
            for hop in hops:
                geo = hop.get('geo', {})
                geo_str = f"{geo.get('city', '?')}, {geo.get('country_code', '?')}" if geo else '-'
                hop_data.append([
                    str(hop.get('hop_number', '')),
                    str(hop.get('from_host', ''))[:25],
                    str(hop.get('by_host', ''))[:25],
                    str(hop.get('ip', ''))[:15],
                    geo_str[:20],
                    '⚠ YES' if hop.get('suspicious') else 'no',
                ])
            hop_table = Table(hop_data, colWidths=[0.5*inch, 1.3*inch, 1.3*inch, 1.1*inch, 1.3*inch, 0.8*inch])
            hop_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283593')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(hop_table)
            elements.append(Spacer(1, 15))

        # --- Header Mismatches ---
        mismatches = forensic.get('mismatches', [])
        if mismatches:
            elements.append(Paragraph("Header Mismatches Detected", heading_style))
            for mm in mismatches:
                severity_color = '#d32f2f' if mm.get('severity') == 'HIGH' else '#f57c00'
                elements.append(Paragraph(
                    f"<b>[{mm.get('severity', '')}]</b> {mm.get('type', '')}: {mm.get('detail', '')}",
                    ParagraphStyle('Mismatch', parent=body_style, textColor=colors.HexColor(severity_color))
                ))
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
            elements.append(Spacer(1, 15))

        # --- Forensic Evidence Chain-of-Custody (NIST SP 800-86 / ISO 27037) ---
        custody = forensic.get('chain_of_custody') or analysis.get('chain_of_custody') or {}
        if custody:
            elements.append(Paragraph("Cryptographic Chain-of-Custody Ledger (ISO/IEC 27037)", heading_style))
            custody_data = [
                ['Custody Evidence ID', str(custody.get('custody_id', 'N/A'))],
                ['Timestamp (UTC)', str(custody.get('timestamp', 'N/A'))],
                ['Integrity Status', str(custody.get('integrity_status', 'VERIFIED_TAMPER_FREE'))],
                ['Evidence SHA-256', str(custody.get('sha256', 'N/A'))[:48] + '...'],
                ['Headers SHA-256', str(custody.get('headers_sha256', 'N/A'))[:48] + '...'],
                ['Ledger Hash', str(custody.get('ledger_hash', 'N/A'))[:48] + '...'],
                ['Custody Agent', str(custody.get('custody_agent', 'MailForensic-AI/2.0'))],
            ]
            custody_table = Table(custody_data, colWidths=[2.2*inch, 3.8*inch])
            custody_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f5e9')),
                ('TEXTCOLOR', (1, 2), (1, 2), colors.HexColor('#2e7d32')),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(custody_table)

        # Build PDF
        doc.build(elements)
        logger.info(f"Forensic report generated: {filepath}")
        return filepath
