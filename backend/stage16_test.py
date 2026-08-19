from fastapi.testclient import TestClient
from fastapi import Request

from src.api.app import app
from src.api.session import session_manager
import src.api.reports as reports


sid = session_manager.create_session({
    "authenticated": True,
    "email": "stage16@test.local",
    "credentials": object(),
})


def fake_get_message(request, message_id):
    return {
        "id": message_id,
        "thread_id": message_id,
        "from": "attacker@example.com",
        "to": "user@example.com",
        "subject": "Stage 16 Report Test",
        "date": "2026-08-18",
        "analysis": {
            "decision": {
                "verdict": "SUSPICIOUS",
                "confidence": 85,
                "recommendations": [
                    "Do not click suspicious links.",
                    "Verify the sender independently."
                ]
            },
            "reasoning": {
                "risk_score": 75,
                "evidence": {
                    "authentication": [
                        "SPF passed",
                        "DKIM passed"
                    ],
                    "url": [
                        "Suspicious domain detected"
                    ]
                }
            }
        }
    }


reports.get_message = fake_get_message


@app.get("/_stage16_session")
def stage16_session(request: Request):
    request.session["session_id"] = sid
    return {"ok": True}


c = TestClient(app)

print("=== STAGE 16 REPORTS TEST ===")

s = c.get("/_stage16_session")
print("SESSION SET:", s.status_code, s.json())
print("SESSION COOKIE:", bool(c.cookies.get("session")))

status = c.get("/auth/status")
print("AUTH STATUS:", status.status_code, status.json())

rj = c.get("/reports/json/STAGE16_TEST")
print("JSON AUTH:", rj.status_code, rj.headers.get("content-type"))
print("JSON DISPOSITION:", rj.headers.get("content-disposition"))
print("JSON VALID:", isinstance(rj.json(), dict) if rj.status_code == 200 else False)

rp = c.get("/reports/pdf/STAGE16_TEST")
print("PDF AUTH:", rp.status_code, rp.headers.get("content-type"))
print("PDF DISPOSITION:", rp.headers.get("content-disposition"))
print("PDF SIGNATURE:", rp.content[:5])
print("PDF SIZE:", len(rp.content))

session_manager.delete_session(sid)

print(
    "SESSION CLEANED:",
    session_manager.get_session(sid) is None
)

print("STAGE16 REPORTS TEST: DONE")