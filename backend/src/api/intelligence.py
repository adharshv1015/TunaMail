"""
Intelligence API Router for TunaMail Stage 5.

All endpoints require authentication (401 if unauthenticated).
Uses the existing SessionManager pattern from gmail.py.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List
import json
import logging

from src.api.session import session_manager
from src.intelligence.db import get_db, rows_to_list, init_db
from src.intelligence.case_manager import CaseManager
from src.intelligence.audit_log import AuditLog
from src.intelligence.campaign_detector import CampaignDetector


logger = logging.getLogger(__name__)
router = APIRouter()

# Ensure DB is initialized
try:
    init_db()
except Exception as e:
    logger.warning(f"Intelligence API DB init: {e}")


def _require_auth(request: Request) -> dict:
    """Reusable auth check — raises 401 if not authenticated."""
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return server_session


# ---- Request Models ----

class CreateCaseRequest(BaseModel):
    title: str
    messages: Optional[List[str]] = []
    iocs: Optional[List[str]] = []
    domains: Optional[List[str]] = []


class AddNoteRequest(BaseModel):
    note: str


class UpdateCaseStatusRequest(BaseModel):
    status: str


# ---- Endpoints ----

@router.get("/message/{message_id}")
def get_message_intelligence(request: Request, message_id: str):
    """
    Get the full intelligence record for a specific message.
    Returns IOCs, entities, related messages, campaigns, attack patterns, trust scores, timeline.
    """
    _require_auth(request)

    iocs = []
    related = []
    campaigns = []

    try:
        with get_db() as conn:
            # IOCs for this message
            ioc_rows = conn.execute(
                "SELECT * FROM ioc_records WHERE message_id = ?", (message_id,)
            ).fetchall()
            iocs = rows_to_list(ioc_rows)

            # Related messages (messages sharing IOCs with this one)
            if iocs:
                normalized_vals = [r["normalized"] for r in ioc_rows]
                placeholders = ",".join("?" * len(normalized_vals))
                related_rows = conn.execute(
                    f"""SELECT DISTINCT message_id, type, normalized, value FROM ioc_records
                        WHERE normalized IN ({placeholders}) AND message_id != ?
                        LIMIT 20""",
                    normalized_vals + [message_id]
                ).fetchall()
                # Group by message_id
                related_map = {}
                for r in related_rows:
                    mid = r["message_id"]
                    if mid not in related_map:
                        related_map[mid] = {"message_id": mid, "shared_indicators": []}
                    related_map[mid]["shared_indicators"].append({
                        "type": r["type"], "value": r["normalized"]
                    })
                related = list(related_map.values())

            # Campaigns containing this message
            campaign_rows = conn.execute(
                "SELECT * FROM campaigns WHERE related_messages LIKE ?",
                (f'%"{message_id}"%',)
            ).fetchall()
            for cr in campaign_rows:
                c = dict(cr)
                try:
                    c["shared_indicators"] = json.loads(c.get("shared_indicators", "[]"))
                    c["related_messages"] = json.loads(c.get("related_messages", "[]"))
                except Exception:
                    pass
                campaigns.append(c)

    except Exception as e:
        logger.error(f"intelligence/message/{message_id} DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    AuditLog().log("email_viewed", {"message_id": message_id})

    return {
        "message_id": message_id,
        "iocs": iocs,
        "related_messages": related,
        "campaigns": campaigns,
    }


@router.get("/ioc/{ioc_value}")
def get_ioc_intelligence(request: Request, ioc_value: str):
    """
    Look up historical intelligence for a specific IOC value.
    """
    _require_auth(request)

    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_records WHERE normalized = ? OR value = ? ORDER BY last_seen DESC",
                (ioc_value.lower(), ioc_value)
            ).fetchall()
            ioc_history = rows_to_list(rows)

            temporal_row = conn.execute(
                "SELECT * FROM indicators WHERE indicator = ?", (ioc_value.lower(),)
            ).fetchone()
            temporal = dict(temporal_row) if temporal_row else {}

    except Exception as e:
        logger.error(f"intelligence/ioc DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    return {
        "value": ioc_value,
        "history": ioc_history,
        "temporal": temporal,
        "occurrences": temporal.get("occurrences", len(ioc_history)),
        "first_seen": temporal.get("first_seen"),
        "last_seen": temporal.get("last_seen")
    }


@router.get("/related/{message_id}")
def get_related_messages(request: Request, message_id: str):
    """
    Find messages related to the given message by shared IOCs.
    """
    _require_auth(request)

    try:
        with get_db() as conn:
            ioc_rows = conn.execute(
                "SELECT normalized, type FROM ioc_records WHERE message_id = ?", (message_id,)
            ).fetchall()

            if not ioc_rows:
                return {"message_id": message_id, "related": [], "shared_indicators": []}

            normalized_vals = list({r["normalized"] for r in ioc_rows})
            placeholders = ",".join("?" * len(normalized_vals))

            related_rows = conn.execute(
                f"""SELECT message_id, type, normalized FROM ioc_records
                    WHERE normalized IN ({placeholders}) AND message_id != ?
                    LIMIT 30""",
                normalized_vals + [message_id]
            ).fetchall()

            related_map = {}
            for r in related_rows:
                mid = r["message_id"]
                if mid not in related_map:
                    related_map[mid] = {"message_id": mid, "shared_indicators": []}
                ind = {"type": r["type"], "value": r["normalized"]}
                if ind not in related_map[mid]["shared_indicators"]:
                    related_map[mid]["shared_indicators"].append(ind)

    except Exception as e:
        logger.error(f"intelligence/related DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    return {
        "message_id": message_id,
        "related": list(related_map.values()),
        "shared_indicators": normalized_vals
    }


@router.get("/campaign/{campaign_id}")
def get_campaign(request: Request, campaign_id: str):
    """
    Get details for a specific campaign.
    """
    _require_auth(request)

    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
            ).fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Campaign not found.")

            campaign = dict(row)
            for field in ("shared_indicators", "related_messages"):
                try:
                    campaign[field] = json.loads(campaign.get(field, "[]"))
                except Exception:
                    campaign[field] = []

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"intelligence/campaign DB error: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    return campaign

# ---- Case Management ----

@router.post("/cases")
def create_case(request: Request, body: CreateCaseRequest):
    """Create a new investigation case."""
    _require_auth(request)
    cm = CaseManager()
    result = cm.create_case(
        title=body.title,
        messages=body.messages,
        iocs=body.iocs,
        domains=body.domains
    )
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("message", "Case creation failed"))
    return result


@router.get("/cases")
def list_cases(request: Request):
    """List all investigation cases."""
    _require_auth(request)
    cm = CaseManager()
    return {"cases": cm.list_cases()}


@router.get("/cases/{case_id}")
def get_case(request: Request, case_id: str):
    """Get details for a specific investigation case."""
    _require_auth(request)
    cm = CaseManager()
    case = cm.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@router.post("/cases/{case_id}/notes")
def add_case_note(request: Request, case_id: str, body: AddNoteRequest):
    """Add a note to an investigation case."""
    _require_auth(request)
    cm = CaseManager()
    result = cm.add_note(case_id=case_id, note=body.note)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Failed to add note"))
    return result


@router.patch("/cases/{case_id}/status")
def update_case_status(request: Request, case_id: str, body: UpdateCaseStatusRequest):
    """Update the status of an investigation case."""
    _require_auth(request)
    cm = CaseManager()
    result = cm.update_status(case_id=case_id, status=body.status)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Failed to update status"))
    return result


@router.get("/audit-log")
def get_audit_log(request: Request):
    """Get recent audit log entries. No credentials are included."""
    _require_auth(request)
    audit = AuditLog()
    return {"entries": audit.get_recent(limit=100)}
