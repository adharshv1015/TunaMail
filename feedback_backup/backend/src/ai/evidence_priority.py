# ============================================================
# backend/src/ai/evidence_priority.py
# ============================================================

EVIDENCE_PRIORITY = {
    "CRITICAL_DETERMINISTIC": 100,
    "STRONG_DETERMINISTIC": 90,
    "CONTRADICTION": 80,
    "URL_INTELLIGENCE": 70,
    "AUTHENTICATION": 60,
    "LOCAL_AI": 50,
    "BEHAVIORAL": 40,
    "REPUTATION": 30,
    "CONTEXTUAL": 20,
}


def get_priority(source):

    source = str(source or "").upper()

    for key, value in EVIDENCE_PRIORITY.items():

        if key in source:
            return value

    return 10
