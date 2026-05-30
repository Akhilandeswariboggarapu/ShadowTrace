# ShadowTrace - Module 5: Report Generator
# Generates a professional PDF forensic case report

import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def load_alerts(filepath):
    """Load alerts from JSON file"""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return []

def generate_report():
    """Generate a professional PDF forensic case report"""
    print("\n📄 ShadowTrace - Generating PDF Report...")
    print("=" * 50)

    # Load all alerts
    network_alerts      = load_alerts('reports/network_alerts.json')
    antiforensics_alerts = load_alerts('reports/antiforensics_alerts.json')
    artifact_alerts     = load_alerts('reports/artifact_alerts.json')
    all_alerts          = network_alerts + antiforensics_alerts + artifact_alerts

    high_alerts = [a for a in all_alerts if a.get('severity') == 'HIGH']
    med_alerts  = [a for a in all_alerts if a.get('severity') == 'MEDIUM']

    # Setup PDF
    output_path = 'reports/ShadowTrace_Forensic_Report.pdf'
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle('title',
        fontSize=22, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1a1a2e'),
        alignment=TA_CENTER, spaceAfter=6)

    subtitle_style = ParagraphStyle('subtitle',
        fontSize=11, fontName='Helvetica',
        textColor=colors.HexColor('#444444'),
        alignment=TA_CENTER, spaceAfter=4)

    section_style = ParagraphStyle('section',
        fontSize=13, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1a1a2e'),
        spaceBefore=14, spaceAfter=6)

    body_style = ParagraphStyle('body',
        fontSize=10, fontName='Helvetica',
        textColor=colors.HexColor('#333333'),
        spaceAfter=4)

    # ── Title Page ───────────────────────────────────
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph("🕵️ ShadowTrace", title_style))
    elements.append(Paragraph("Forensic Investigation Report", title_style))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#e63946')))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph("Case: Unauthorized Web Activity & Anti-Forensics Behavior", subtitle_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(Paragraph("Investigator: Akhilandeswari Boggarapu", subtitle_style))
    elements.append(Spacer(1, 0.3*inch))

    # ── Executive Summary ────────────────────────────
    elements.append(Paragraph("Executive Summary", section_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.1*inch))

    summary_text = f"""
    ShadowTrace conducted a full digital forensic investigation into suspected unauthorized 
    web activity and anti-forensics behavior within an enterprise environment. 
    The investigation analyzed network traffic logs, browser artifacts, and system-level 
    indicators across three independent detection modules. A total of <b>{len(all_alerts)} alerts</b> 
    were identified, of which <b>{len(high_alerts)} are HIGH severity</b> and 
    <b>{len(med_alerts)} are MEDIUM severity</b>. Evidence strongly suggests deliberate 
    use of anonymization tools and active attempts to conceal investigative traces.
    """
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 0.2*inch))

    # ── Alert Summary Table ──────────────────────────
    elements.append(Paragraph("Alert Summary", section_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.1*inch))

    summary_data = [
        ['Module', 'Alerts Found', 'High', 'Medium'],
        ['Module 1 — Network Analyzer',
            str(len(network_alerts)),
            str(len([a for a in network_alerts if a.get('severity')=='HIGH'])),
            str(len([a for a in network_alerts if a.get('severity')=='MEDIUM']))],
        ['Module 2 — Anti-Forensics Detector',
            str(len(antiforensics_alerts)),
            str(len([a for a in antiforensics_alerts if a.get('severity')=='HIGH'])),
            str(len([a for a in antiforensics_alerts if a.get('severity')=='MEDIUM']))],
        ['Module 3 — Artifact Recovery',
            str(len(artifact_alerts)),
            str(len([a for a in artifact_alerts if a.get('severity')=='HIGH'])),
            str(len([a for a in artifact_alerts if a.get('severity')=='MEDIUM']))],
        ['TOTAL', str(len(all_alerts)), str(len(high_alerts)), str(len(med_alerts))],
    ]

    table = Table(summary_data, colWidths=[3*inch, 1.2*inch, 1*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,0), 10),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#e63946')),
        ('TEXTCOLOR',  (0,-1), (-1,-1), colors.white),
        ('FONTNAME',   (0,-1), (-1,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.HexColor('#f8f8f8'), colors.white]),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('ROWHEIGHT',  (0,0), (-1,-1), 20),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.3*inch))

    # ── Detailed Alerts ──────────────────────────────
    for module_name, alert_list in [
        ("Module 1 — Network Alerts",           network_alerts),
        ("Module 2 — Anti-Forensics Alerts",    antiforensics_alerts),
        ("Module 3 — Artifact Recovery Alerts", artifact_alerts),
    ]:
        elements.append(Paragraph(module_name, section_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
        elements.append(Spacer(1, 0.1*inch))

        if not alert_list:
            elements.append(Paragraph("No alerts found for this module.", body_style))
        else:
            detail_data = [['Severity', 'Type', 'Detail', 'Timestamp']]
            for alert in alert_list:
                detail_data.append([
                    alert.get('severity', 'N/A'),
                    alert.get('type', 'N/A'),
                    alert.get('detail', 'N/A')[:55],
                    str(alert.get('timestamp', 'N/A'))[:19],
                ])

            det_table = Table(detail_data, colWidths=[0.8*inch, 1.6*inch, 3*inch, 1.4*inch])
            det_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
                ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',   (0,0), (-1,-1), 8),
                ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8f8f8'), colors.white]),
                ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWHEIGHT',  (0,0), (-1,-1), 18),
            ]))
            elements.append(det_table)
        elements.append(Spacer(1, 0.2*inch))

    # ── Conclusion ───────────────────────────────────
    elements.append(Paragraph("Conclusion", section_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.1*inch))
    conclusion = """
    The ShadowTrace investigation successfully identified and documented evidence of unauthorized 
    web activity and deliberate anti-forensics behavior. The combination of TOR/VPN usage, 
    large data transfers during after-hours periods, cleared browser history, and the presence 
    of evidence-wiping tools presents a comprehensive and compelling forensic case. 
    All findings have been preserved in structured JSON reports and this PDF document 
    for use in further proceedings.
    """
    elements.append(Paragraph(conclusion, body_style))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#e63946')))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph("ShadowTrace | Akhilandeswari Boggarapu | 2024", subtitle_style))

    # Build PDF
    doc.build(elements)
    print(f"✅ PDF Report saved to: {output_path}")
    return output_path

if __name__ == "__main__":
    generate_report()