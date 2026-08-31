/**
 * TunaMail Stage 5 — Intelligence API helpers.
 * All endpoints require an authenticated session.
 */

import api from "../services/api";

const BASE = "/intelligence";

/** Get full intelligence record for a message */
export const getMessageIntelligence = (messageId) =>
  api.get(`${BASE}/message/${messageId}`);

/** Lookup IOC history */
export const getIOCIntelligence = (iocValue) =>
  api.get(`${BASE}/ioc/${encodeURIComponent(iocValue)}`);

/** Get related messages by IOC */
export const getRelatedMessages = (messageId) =>
  api.get(`${BASE}/related/${messageId}`);

/** Get campaign details */
export const getCampaign = (campaignId) =>
  api.get(`${BASE}/campaign/${campaignId}`);

/** Submit analyst verdict override (automated verdict preserved separately) */
export const submitAnalystVerdict = (messageId, analystVerdict, comment = "") =>
  api.post(`${BASE}/analyst-verdict`, {
    message_id: messageId,
    analyst_verdict: analystVerdict,
    comment,
  });

/** Create investigation case */
export const createCase = (title, messages = [], iocs = [], domains = []) =>
  api.post(`${BASE}/cases`, { title, messages, iocs, domains });

/** List all investigation cases */
export const listCases = () => api.get(`${BASE}/cases`);

/** Get case details */
export const getCase = (caseId) => api.get(`${BASE}/cases/${caseId}`);

/** Add note to case */
export const addCaseNote = (caseId, note) =>
  api.post(`${BASE}/cases/${caseId}/notes`, { note });

/** Update case status */
export const updateCaseStatus = (caseId, status) =>
  api.patch(`${BASE}/cases/${caseId}/status`, { status });

/** Get audit log */
export const getAuditLog = () => api.get(`${BASE}/audit-log`);
