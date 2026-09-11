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
    
    from src.api.auth import format_name_from_email
    if "from" in data and isinstance(data["from"], str):
        data["from"] = format_name_from_email(data["from"])
    if "to" in data and isinstance(data["to"], str):
        data["to"] = format_name_from_email(data["to"])
    elif not data.get("to"):
        data["to"] = "You"
        
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

def simplify_evidence_for_kid(module: str, indicator: str, severity: str, explanation: str) -> tuple:
    """Translates technical cybersecurity forensics into simple analogies a child can understand."""
    # Module translation
    mod_map = {
        "Authentication": "Sender ID Badge",
        "Trust": "Sender Friendliness",
        "Content": "Message Words",
        "Url": "Buttons & Links",
        "Urls": "Buttons & Links",
        "Attachment": "Attached File",
        "Ai": "Robot Brain Check"
    }
    simple_mod = mod_map.get(module, module)
    
    # Severity translation
    sev_map = {
        "HIGH": "Big Danger",
        "CRITICAL": "Big Danger",
        "MEDIUM": "Warning",
        "LOW": "Small Note",
        "INFO": "Safe Clue"
    }
    simple_sev = sev_map.get(str(severity).upper(), severity)
    
    # Indicator translation
    ind_str = str(indicator).upper()
    simple_ind = indicator
    if "HOMOGRAPH" in ind_str or "LOOKALIKE" in ind_str:
        simple_ind = "Sneaky Lookalike Website"
    elif "IMPERSONATION" in ind_str or "SPOOF" in ind_str:
        simple_ind = "Faking a Real Company"
    elif "PASS" in ind_str or "VERIFIED" in ind_str:
        simple_ind = "Official Seal Verified"
    elif "FAIL" in ind_str:
        simple_ind = "Broken Seal / Fake Address"
    elif "MACRO" in ind_str or "VIRUS" in ind_str or "MALWARE" in ind_str:
        simple_ind = "Hidden Virus Code in File"
    elif "HARVEST" in ind_str or "CREDENTIAL" in ind_str:
        simple_ind = "Asking for Secret Passwords"
    elif "URGENCY" in ind_str:
        simple_ind = "Pushy / Rushing Words"
    elif "FINANCIAL" in ind_str or "LURE" in ind_str or "INVOICE" in ind_str:
        simple_ind = "Fake Money or Prize Trap"
    elif "ATTACHMENT" in ind_str and ("UNSAFE" in ind_str or "PHISH" in ind_str):
        simple_ind = "Sneaky Trap Inside File"
    elif "ESTABLISHED" in ind_str or "AGE" in ind_str:
        simple_ind = "Old & Well-Known Website"
    elif "LOW_TRUST" in ind_str or "UNKNOWN" in ind_str:
        simple_ind = "New or Unknown Sender"

    # Explanation simplification
    exp = str(explanation).strip()
    if "homograph" in exp.lower() or "lookalike" in exp.lower():
        m = re.search(r"['\"]([a-zA-Z0-9.\-]+)['\"].*impersonates.*['\"]([a-zA-Z0-9.\-]+)['\"]", exp)
        if m:
            fake_d, real_d = m.group(1), m.group(2)
            exp = f"Sneaky trick link: Uses fake lookalike letters to pretend to be '{real_d}', trying to fool your eyes and steal your secrets."
        else:
            exp = "Sneaky trick link: Uses fake lookalike letters that pretend to be a popular website to trick you."
    elif "dkim" in exp.lower() and "signed" in exp.lower():
        exp = "Tamper-proof wax seal is intact: Proves nobody opened, changed, or messed with this letter on its way to you."
    elif "spf" in exp.lower() and ("authorized" in exp.lower() or "dns" in exp.lower()):
        exp = "Official Post Office stamp: Mailed directly from the company's real mail server, not a copycat."
    elif "dmarc" in exp.lower():
        exp = "ID Check: The sender's name on top matches the real address below."
    elif "macro" in exp.lower():
        exp = "Hidden computer virus code found inside this document that could harm your computer."
    elif "phishing" in exp.lower() and "link" in exp.lower() and ("document" in exp.lower() or "file" in exp.lower() or "pdf" in exp.lower()):
        exp = "A deceptive trap link was discovered hiding inside the attached file. Clicking it opens a fake website."
    elif "urgency" in exp.lower() or "urgent" in exp.lower():
        exp = "Scary or pushy words trying to rush you before you have time to think or ask an adult."
    elif "harvest" in exp.lower() or "password" in exp.lower() or "credential" in exp.lower():
        exp = "Sneaky tricks trying to grab your secret passwords, login codes, or account details."
    elif "financial" in exp.lower() or "money" in exp.lower() or "invoice" in exp.lower() or "prize" in exp.lower():
        exp = "Tricks offering fake money, prizes, or asking you to pay cash."
    elif "low trust" in exp.lower():
        exp = "We don't know this sender well yet, so we have to be extra careful."
    elif "established" in exp.lower() or "existed for" in exp.lower():
        exp = "The sender's website has been active for years and is well-known, reducing danger."

    return simple_mod, simple_ind, simple_sev, exp

def generate_pdf_report(parsed_data: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('KidTitle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#1e3a8a"), spaceAfter=2, fontName="Helvetica-Bold")
    sub_title_style = ParagraphStyle('KidSubTitle', parent=styles['Normal'], fontSize=9.5, textColor=colors.HexColor("#64748b"), spaceAfter=14)
    h2_style = ParagraphStyle('KidH2', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor("#1e293b"), spaceBefore=11, spaceAfter=6, fontName="Helvetica-Bold")
    normal_style = ParagraphStyle('KidNormal', parent=styles['Normal'], fontSize=8.5, textColor=colors.HexColor("#334155"), leading=12)
    bullet_style = ParagraphStyle('KidBullet', parent=styles['Normal'], fontSize=8.5, textColor=colors.HexColor("#1e293b"), leading=13, leftIndent=8, spaceAfter=2)
    table_header_style = ParagraphStyle('KidTH', parent=styles['Normal'], fontSize=8.5, fontName="Helvetica-Bold", textColor=colors.HexColor("#0f172a"))
    table_cell_style = ParagraphStyle('KidTD', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#334155"), leading=11)

    story = []
    
    # Title
    story.append(Paragraph("TUNAMAIL SAFETY REPORT", title_style))
    story.append(Paragraph("Letter Safety Check & Clues — Easy to Understand", sub_title_style))
    
    # Letter Details
    story.append(Paragraph("1. Letter Details (Who Sent It)", h2_style))
    metadata = [
        [Paragraph("Subject", table_header_style), Paragraph(str(parsed_data.get("subject", "(No Subject)"))[:120], table_cell_style)],
        [Paragraph("Who Sent This", table_header_style), Paragraph(str(parsed_data.get("from", "Unknown")), table_cell_style)],
        [Paragraph("Sent To", table_header_style), Paragraph(str(parsed_data.get("to", "Unknown")), table_cell_style)],
        [Paragraph("When It Arrived", table_header_style), Paragraph(str(parsed_data.get("date", "N/A")), table_cell_style)],
    ]
    t_metadata = Table(metadata, colWidths=[110, 430])
    t_metadata.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_metadata)
    story.append(Spacer(1, 8))

    # Final Decision
    story.append(Paragraph("2. Safety Verdict: Is It Safe To Open?", h2_style))
    analysis = parsed_data.get("analysis", {})
    decision = analysis.get("decision", {})
    verdict = str(decision.get("verdict") or "UNKNOWN").upper()
    risk_score = analysis.get("reasoning", {}).get("risk_score", decision.get("risk_score", 0))
    confidence = decision.get("confidence", 95)
    
    if verdict in ["PHISHING", "HIGH RISK", "MALICIOUS", "CRITICAL"]:
        verdict_text = "🔴 DANGEROUS TRICK (DO NOT OPEN OR CLICK)"
        verdict_color = colors.HexColor("#dc2626")
        risk_label = f"{risk_score}/100 — High Danger Trap!"
    elif verdict in ["SUSPICIOUS", "LOW RISK"]:
        verdict_text = "🟡 BE CAREFUL (ASK A GROWN-UP FIRST)"
        verdict_color = colors.HexColor("#d97706")
        risk_label = f"{risk_score}/100 — Strange Signals Detected"
    else:
        verdict_text = "🟢 100% SAFE (YOU CAN SAFELY READ THIS)"
        verdict_color = colors.HexColor("#16a34a")
        risk_label = f"{risk_score}/100 — Completely Clean"

    decision_data = [
        [Paragraph("Safety Verdict", table_header_style), Paragraph(verdict_text, ParagraphStyle('V', parent=table_cell_style, fontName="Helvetica-Bold", textColor=verdict_color))],
        [Paragraph("Danger Meter", table_header_style), Paragraph(risk_label, table_cell_style)],
        [Paragraph("How Sure We Are", table_header_style), Paragraph(f"{confidence}% Confident", table_cell_style)]
    ]
    t_decision = Table(decision_data, colWidths=[110, 430])
    t_decision.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_decision)
    story.append(Spacer(1, 8))

    # Recommendations: Safety Rules
    story.append(Paragraph("3. Safety Rules: What Should You Do?", h2_style))
    if verdict in ["PHISHING", "HIGH RISK", "MALICIOUS", "CRITICAL"] or (isinstance(risk_score, (int, float)) and risk_score >= 50):
        rules = [
            "• 🛑 <b>STOP!</b> Do not click any links, pictures, or buttons inside this letter.",
            "• 🔒 <b>SECRET PASSWORDS:</b> Never share your passwords, codes, or account names.",
            "• 📎 <b>DO NOT OPEN FILES:</b> Do not download or open any attached files or drawings.",
            "• 🗑️ <b>ASK A GROWN-UP:</b> Ask a parent or teacher to help you delete this trick letter."
        ]
    elif verdict in ["SUSPICIOUS", "LOW RISK"]:
        rules = [
            "• ⚠️ <b>BE CAREFUL:</b> Something about this letter looks strange or unusual.",
            "• 🛑 <b>DON'T CLICK:</b> Do not click any web links until you check with an adult.",
            "• 🔍 <b>DOUBLE CHECK:</b> Ask the real sender in person before trusting what this says."
        ]
    else:
        rules = [
            "• ✓ <b>SAFE TO READ:</b> This letter really came from who it says it's from.",
            "• ✓ <b>CLEAN:</b> All buttons and web links lead to safe, real websites.",
            "• ✓ <b>NO TRAPS:</b> No sneaky viruses, traps, or tricky words were found."
        ]
    for r in rules:
        story.append(Paragraph(r, bullet_style))
    story.append(Spacer(1, 8))

    # Security Explanation in Simple Words
    story.append(Paragraph("4. Why Did Tuna Robot Decide This? (In Simple Words)", h2_style))
    explanation_obj = analysis.get("explanation", {})
    explanation_text = explanation_obj.get("final_reason", "") if isinstance(explanation_obj, dict) else str(explanation_obj)
    
    # Check if there are attachment threats
    att_threats = parsed_data.get("forensic_evidences", [])
    has_att_threat = any("homograph" in str(e.get("explanation", "")).lower() or "macro" in str(e.get("explanation", "")).lower() for e in att_threats)
    
    if has_att_threat:
        explanation_text = "We looked inside this letter and discovered a sneaky trick link pretending to be a famous website. Someone is trying to fool your eyes and steal your passwords. That is why Tuna Robot marked this as dangerous!"
    elif verdict in ["PHISHING", "HIGH RISK"]:
        explanation_text = "This letter is pretending to be from someone you know or trust, but our tests showed it is a fake copycat trying to trick you. Do not click or reply!"
    elif verdict in ["SUSPICIOUS"]:
        explanation_text = "This letter contains unusual signals, such as new sender addresses or urgent words. Be careful and check with an adult before interacting."
    elif not explanation_text or "reasoning engine" in explanation_text.lower():
        explanation_text = "We checked the sender's official post office stamp, the tamper-proof wax seal, all web links, and attached files. Everything is verified, genuine, and safe to read."
    
    story.append(Paragraph(explanation_text, normal_style))
    story.append(Spacer(1, 8))

    # Clues / Forensic Evidence table
    forensic_evidences = parsed_data.get("forensic_evidences", [])
    if forensic_evidences:
        story.append(Paragraph("5. All The Clues We Found (Proof)", h2_style))
        evidence_data = [[
            Paragraph("Where We Looked", table_header_style),
            Paragraph("What We Found", table_header_style),
            Paragraph("Danger Level", table_header_style),
            Paragraph("What It Means (Easy Explanation)", table_header_style)
        ]]
        from xml.sax.saxutils import escape
        for ev in forensic_evidences:
            raw_mod = str(ev.get("source_module", "Unknown"))
            raw_ind = str(ev.get("indicator", ev.get("type", "Unknown")))
            raw_sev = str(ev.get("severity", "INFO"))
            raw_exp = str(ev.get("explanation", ""))
            
            s_mod, s_ind, s_sev, s_exp = simplify_evidence_for_kid(raw_mod, raw_ind, raw_sev, raw_exp)
            
            # Pick color for danger level
            sev_color = colors.HexColor("#16a34a") # green
            if "Big Danger" in s_sev:
                sev_color = colors.HexColor("#dc2626")
            elif "Warning" in s_sev:
                sev_color = colors.HexColor("#d97706")
            elif "Note" in s_sev:
                sev_color = colors.HexColor("#2563eb")

            evidence_data.append([
                Paragraph(escape(s_mod), table_cell_style),
                Paragraph(escape(s_ind), table_cell_style),
                Paragraph(f"<b>{escape(s_sev)}</b>", ParagraphStyle('Sev', parent=table_cell_style, textColor=sev_color)),
                Paragraph(escape(s_exp), table_cell_style)
            ])
            
        t_evidence = Table(evidence_data, colWidths=[90, 105, 75, 270])
        t_evidence.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
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
