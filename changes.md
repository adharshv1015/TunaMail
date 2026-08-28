# TLS Policy Violation Changes

This document outlines the modifications made to prevent standard TLS policy violations (like untrusted issuers or self-signed certificates) from automatically triggering a `PHISHING` or `HIGH RISK` verdict in the analysis engine.

Previously, `TLS_POLICY_VIOLATION` was hardcoded into the `STRONG_NEGATIVE_TYPES` and `STRONG_TYPES` sets across multiple decision engines. This caused medium-severity TLS issues to be improperly weighted alongside critical security threats.

## Files Modified

### 1. `backend/src/engines/decision_fusion_engine.py`
- Removed `"TLS_POLICY_VIOLATION"` from the `STRONG_NEGATIVE_TYPES` set.
- Created a new `medium_patterns` dictionary in the `_fallback_negative_from_reasoning` method to handle legacy evidence mapping.
- Mapped `"tls policy violation"` to `MEDIUM` severity instead of `HIGH` in the fallback logic.

### 2. `backend/src/engines/decision_fusion_guard.py`
- Removed `"TLS_POLICY_VIOLATION"` from the `STRONG_NEGATIVE_TYPES` set.
- Lowered the mapped severity for `"tls policy violation"` from `"HIGH"` to `"MEDIUM"` in the `_collect_legacy_evidence` function.

### 3. `backend/src/engines/decision_consistency_validator.py`
- Removed `"TLS_POLICY_VIOLATION"` from the `STRONG_TYPES` set.

### 4. `backend/src/engines/decision_validator.py`
- Removed `"TLS_POLICY_VIOLATION"` from the `STRONG_NEGATIVE_TYPES` set.

### 5. `backend/src/engines/evidence_conflict_engine.py`
- Removed `"TLS_POLICY_VIOLATION"` from the `STRONG_TYPES` set.

## Impact
- **Untrusted Issuers & Self-Signed Certs**: These are now correctly evaluated as `MEDIUM` severity issues. They will add to the overall risk score but will not trigger immediate `PHISHING` verdicts on their own.
- **Hostname Mismatches**: These are inherently classified as `HIGH` severity by the `URLInspectionService`. Since they are `HIGH` severity, they will still be caught by the engine as strong negative evidence based on their severity level (e.g. `severity in {"HIGH", "CRITICAL"}`).
