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
            
    # Evidence
    story.append(Paragraph("Evidence", h2_style))
    evidence = analysis.get("reasoning", {}).get("evidence", {})
    for category, items in evidence.items():
        if items:
            story.append(Paragraph(category.capitalize(), styles['Heading3']))
            for item in items:
                # Escape untrusted content before passing it to ReportLab's
                # HTML-like paragraph parser.
                from xml.sax.saxutils import escape

                safe_item = (
                    str(item)
                    .replace('✓', '')
                    .replace('⚠', '')
                    .strip()
                )
                safe_item = escape(safe_item)

                prefix = (
                    "[+]"
                    if "pass" in safe_item.lower() or "clean" in safe_item.lower()
                    else "[-]"
                )

                story.append(
                    Paragraph(
                        f"{prefix} {safe_item}",
                        normal_style
                    )
                )
    
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
    pdf_buffer = generate_pdf_report(parsed_data)
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=tunamail_report_{message_id}.pdf"}
    )
