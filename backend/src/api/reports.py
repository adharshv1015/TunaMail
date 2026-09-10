from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import StreamingResponse
import io
import json
from src.api.gmail import get_message
from src.api.session import session_manager

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

router = APIRouter()

import re
from datetime import timezone, timedelta
from email.utils import parsedate_to_datetime

def format_export_data(parsed_data: dict) -> dict:
    import copy
    data = copy.deepcopy(parsed_data)
    
    if "from" in data and isinstance(data["from"], str):
        data["from"] = re.sub(r'<[^>]*>', '', data["from"]).strip()
    if "to" in data and isinstance(data["to"], str):
        data["to"] = re.sub(r'<[^>]*>', '', data["to"]).strip()
        
    if "date" in data and isinstance(data["date"], str) and data["date"] != "N/A":
        try:
            dt = parsedate_to_datetime(data["date"])
            ist = timezone(timedelta(hours=5, minutes=30))
            dt_ist = dt.astimezone(ist)
            data["date"] = dt_ist.strftime("%a, %d %b %Y %I:%M:%S %p (IST)")
        except Exception:
            pass
            
    # Extract all structured evidences for unified forensic view
    analysis = data.get("analysis", {})
    all_evidences = []
    
    modules = ["authentication", "content", "url", "urls", "attachment", "trust", "ai"]
    for mod in modules:
        mod_data = analysis.get(mod)
        if isinstance(mod_data, dict):
            se = mod_data.get("structured_evidence", [])
            for item in se:
                if isinstance(item, dict):
                    import copy as cp
                    new_item = cp.deepcopy(item)
                    new_item["source_module"] = mod.capitalize()
                    all_evidences.append(new_item)
                    
    # Deduplicate and sort by severity
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    
    unique_evidences = []
    seen_exps = set()
    for ev in all_evidences:
        # Safely get explanation as string to avoid unhashable type errors
        exp = str(ev.get("explanation", ""))
        if exp not in seen_exps:
            seen_exps.add(exp)
            unique_evidences.append(ev)
            
    def get_sort_key(x):
        sev = x.get("severity")
        if not isinstance(sev, str):
            sev = "INFO"
        sev_score = severity_order.get(sev.upper(), 4)
        
        conf = x.get("confidence")
        try:
            conf_score = float(conf)
        except (ValueError, TypeError):
            conf_score = 0.0
            
        return (sev_score, -conf_score)
        
    unique_evidences.sort(key=get_sort_key)
    
    data["forensic_evidences"] = unique_evidences
            
    return data

def generate_pdf_report(parsed_data: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#1e3a8a"), spaceAfter=20)
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#374151"), spaceBefore=15, spaceAfter=10)
    normal_style = styles['Normal']
    
    story = []
    
    # Title
    story.append(Paragraph("TUNAMAIL SECURITY REPORT", title_style))
    
    # Email Metadata
    story.append(Paragraph("Email Information", h2_style))
    metadata = [
        ["Subject", parsed_data.get("subject", "N/A")[:100]],
        ["Sender", parsed_data.get("from", "N/A")],
        ["Recipient", parsed_data.get("to", "N/A")],
        ["Date", parsed_data.get("date", "N/A")],
        ["ID", parsed_data.get("id", "N/A")],
    ]
    t_metadata = Table(metadata, colWidths=[100, 400])
    t_metadata.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#111827")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    story.append(t_metadata)
    
    analysis = parsed_data.get("analysis", {})
    decision = analysis.get("decision", {})
    
    # Decision
    story.append(Paragraph("Final Decision", h2_style))
    verdict = decision.get("verdict", "UNKNOWN")
    risk_score = analysis.get("reasoning", {}).get("risk_score", 0)
    confidence = decision.get("confidence", 0)
    
    decision_data = [
        ["Verdict", verdict],
        ["Risk Score", f"{risk_score}/100"],
        ["Confidence", f"{confidence}%"]
    ]
    t_decision = Table(decision_data, colWidths=[100, 400])
    
    verdict_color = colors.green
    if verdict in ["PHISHING", "HIGH RISK"]: verdict_color = colors.red
    elif verdict in ["SUSPICIOUS", "LOW RISK"]: verdict_color = colors.orange
    
    t_decision.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#111827")),
        ('TEXTCOLOR', (1, 0), (1, 0), verdict_color),
        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    story.append(t_decision)
    
    # Recommendations
    if decision.get("recommendations"):
        story.append(Paragraph("Recommendations", h2_style))
        for rec in decision.get("recommendations", []):
            story.append(Paragraph(f"• {rec}", normal_style))
            
    # Security Explanation
    explanation_obj = analysis.get("explanation", {})
    explanation_text = explanation_obj.get("final_reason", "") if isinstance(explanation_obj, dict) else str(explanation_obj)
    
    if explanation_text:
        story.append(Paragraph("Security Explanation", h2_style))
        from xml.sax.saxutils import escape
        story.append(Paragraph(escape(explanation_text).replace('\n', '<br/>'), normal_style))
        
    # Forensic Evidence
    forensic_evidences = parsed_data.get("forensic_evidences", [])
    if forensic_evidences:
        story.append(Paragraph("Forensic Evidences", h2_style))
        evidence_data = [["Module", "Indicator", "Severity", "Explanation"]]
        from xml.sax.saxutils import escape
        for ev in forensic_evidences:
            mod = ev.get("source_module", "Unknown")
            indicator = ev.get("indicator", ev.get("type", "Unknown"))
            severity = ev.get("severity", "INFO")
            explanation = ev.get("explanation", "")
            
            evidence_data.append([
                Paragraph(escape(str(mod)), normal_style),
                Paragraph(escape(str(indicator)), normal_style),
                Paragraph(escape(str(severity)), normal_style),
                Paragraph(escape(str(explanation)), normal_style)
            ])
            
        t_evidence = Table(evidence_data, colWidths=[70, 100, 60, 270])
        t_evidence.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#111827")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ]))
        story.append(t_evidence)
    
    # Generate PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/json/{message_id}")
def export_json(request: Request, message_id: str):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")
        
    parsed_data = get_message(request, message_id)
    parsed_data = format_export_data(parsed_data)
    json_str = json.dumps(parsed_data, indent=2)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=tunamail_report_{message_id}.json"}
    )


@router.get("/pdf/{message_id}")
def export_pdf(request: Request, message_id: str):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")
        
    parsed_data = get_message(request, message_id)
    parsed_data = format_export_data(parsed_data)
    pdf_buffer = generate_pdf_report(parsed_data)
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=tunamail_report_{message_id}.pdf"}
    )
