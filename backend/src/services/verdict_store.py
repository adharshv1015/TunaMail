import json
import os
import time
import hashlib
import logging
import math
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# This version controls the schema/validity of the historical store logic.
# It should be bumped when the fundamentals of what makes a message "safe" change.
SAFE_VERDICT_VERSION = "1.0"

class VerdictStore:
    """
    Persistent store for historical safe verdicts.
    Provides historical context as supporting evidence, NOT a hard safety override.
    """
    
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.store_path = os.path.join(self.data_dir, "verdict_store.json")
        self._ensure_dir()
        self._cache = self._load()

    def _ensure_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load verdict store: {e}")
        return {}

    def _save(self):
        try:
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save verdict store: {e}")

    def generate_message_version(self, parsed_email: dict, url_analysis: dict) -> str:
        """
        hash(normalized_headers + normalized_body + normalized_urls + attachment_fingerprints)
        Strictly isolates the message content to detect evasion attempts via slight modifications.
        """
        # 1. Normalized Headers
        sender = parsed_email.get("from", "").strip().lower()
        subject = parsed_email.get("subject", "").strip()
        
        # 2. Normalized Body
        body = parsed_email.get("body", "").strip()
        
        # 3. Normalized URLs
        urls = []
        if isinstance(url_analysis, dict):
            for u in url_analysis.get("analysis", []):
                urls.append(u.get("url", ""))
        urls = sorted(urls)
        
        # 4. Attachment Fingerprints
        attachments = []
        for a in (parsed_email.get("attachments") or []):
            if isinstance(a, dict):
                attachments.append(f"{a.get('filename', '')}:{a.get('size', 0)}")
        attachments = sorted(attachments)
        
        fingerprint_data = {
            "sender": sender,
            "subject": subject,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:32],
            "urls": urls,
            "attachments": attachments
        }
        
        return hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()

    def calculate_freshness(self, recorded_at: float) -> float:
        """
        Continuous decay from 1.0 down to 0.1 based on age.
        0-30 days   : 1.0 -> ~0.8 (Strong)
        31-180 days : ~0.8 -> ~0.4 (Moderate)
        >180 days   : <0.4 (Weak)
        """
        age_seconds = time.time() - recorded_at
        age_days = age_seconds / (24 * 3600)
        
        if age_days < 0:
            return 1.0
            
        # Exponential decay: f(t) = max(0.1, e^(-k * t))
        # Choose k such that at t=180, f(t) ≈ 0.4
        # k ≈ -ln(0.4) / 180 ≈ 0.00509
        k = 0.00509
        freshness = math.exp(-k * age_days)
        
        return max(0.1, round(freshness, 2))

    def record_if_safe(self, message_id: str, parsed_email: dict, analysis: dict, final_decision: dict):
        """
        Evaluate if the final decision meets strict entry criteria and record it.
        """
        verdict = final_decision.get("verdict")
        confidence = final_decision.get("confidence", 0)
        
        # 1. Base eligibility
        if verdict not in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"] or confidence < 70:
            return
            
        # 2. Strict Entry Criteria Check
        auth = analysis.get("authentication", {})
        auth_pass = (
            auth.get("spf") == "pass" and 
            auth.get("dkim") in ["pass", "present_unverified"] and 
            auth.get("dmarc") == "pass"
        )
        
        url_analysis = analysis.get("url", {})
        
        # Check for significant negative evidence (e.g. from decision reasoning or conflict engine)
        reasoning = final_decision.get("reasoning", {})
        has_network_risk = len(reasoning.get("network", [])) > 0
        has_behavioral_risk = len(reasoning.get("behavioral", [])) > 0
        
        conflict = analysis.get("conflict", {})
        has_unresolved_conflict = conflict.get("unresolved_contradictions", False)
        
        # Must have positive evidence + no significant bad evidence
        if not auth_pass:
            return
        if has_network_risk or has_behavioral_risk:
            return
        if has_unresolved_conflict:
            return
            
        # Optional: check if analyst explicitly confirmed
        confirmed_by_analyst = final_decision.get("confirmed_by_analyst", False)
            
        # 3. Build Record
        msg_version = self.generate_message_version(parsed_email, url_analysis)
        
        record = {
            "message_id": message_id,
            "message_version": msg_version,
            "safe_verdict_version": SAFE_VERDICT_VERSION,
            "historical": {
                "verdict": verdict,
                "confidence": confidence,
                "risk_score": final_decision.get("risk_score", 0),
                "recorded_at": time.time(),
                "analysis_version": os.environ.get("ANALYSIS_VERSION", "unknown")
            },
            "history_state": {
                "conflict_count": 0,
                "confirmed_by_analyst": confirmed_by_analyst
            }
        }
        
        self._cache[message_id] = record
        self._save()

    def get_historical_evidence(self, message_id: str, current_parsed_email: dict, current_url_analysis: dict) -> dict:
        """
        Retrieves historical evidence if valid.
        Distinguishes between VALID_HISTORICAL_EVIDENCE and STALE_HISTORICAL_EVIDENCE.
        """
        record = self._cache.get(message_id)
        if not record:
            return {"status": "NONE"}
            
        # Check Global Versioning
        if record.get("safe_verdict_version") != SAFE_VERDICT_VERSION:
            return {"status": "INACTIVE_VERSION"}
            
        # Check Fingerprint (Message Version) Match
        current_version = self.generate_message_version(current_parsed_email, current_url_analysis)
        if record.get("message_version") != current_version:
            # Mark as stale, contributes zero weight
            return {
                "status": "STALE_HISTORICAL_EVIDENCE",
                "reason": "message_version_mismatch",
                "record": record
            }
            
        # Calculate continuous freshness
        recorded_at = record.get("historical", {}).get("recorded_at", time.time())
        freshness = self.calculate_freshness(recorded_at)
        record["history_state"]["freshness"] = freshness
        
        return {
            "status": "VALID_HISTORICAL_EVIDENCE",
            "record": record
        }
