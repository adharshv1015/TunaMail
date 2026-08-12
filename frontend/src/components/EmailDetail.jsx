import React, { useEffect, useState } from "react";
import { getMessage } from "../api/api";
import EmailHeaders from "./email/EmailHeaders";
import ThreatOverview from "./email/ThreatOverview";
import AuthenticationCard from "./email/AuthenticationCard";
import ContentAnalysisCard from "./email/ContentAnalysisCard";
import URLIntelligence from "./email/URLIntelligence";
import WhoisAnalysis from "./email/WhoisAnalysis";
import AttachmentAnalysis from "./email/AttachmentAnalysis";
import TrustAnalysis from "./email/TrustAnalysis";
import SecurityReasoning from "./email/SecurityReasoning";
import FinalDecision from "./email/FinalDecision";
import AnalystExplanation from "./email/AnalystExplanation";
import EmailContent from "./email/EmailContent";
import TechnicalHeaders from "./email/TechnicalHeaders";
import IntelligenceCard from "./email/IntelligenceCard";
import AdaptiveIntelligence from "./email/AdaptiveIntelligence";

import LoadingSkeleton from "./common/LoadingSkeleton";

function EmailDetail({ messageId }) {
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!messageId) {
      setMessage(null);
      return;
    }

    const controller = new AbortController();
    const { signal } = controller;

    const loadMessage = async () => {
      try {
        setLoading(true);
        setError("");
        console.log("Fetching message:", messageId);
        const data = await getMessage(messageId, { signal });
        console.log("Message detail:", data);
        setMessage(data);
      } catch (err) {
        if (err.name === 'AbortError') {
            console.log("Fetch aborted for message:", messageId);
            return;
        }
        console.error(err);
        setError("Failed to load email analysis.");
      } finally {
        if (!signal.aborted) {
            setLoading(false);
        }
      }
    };

    loadMessage();
    
    return () => {
        controller.abort();
    };
  }, [messageId]);

  /* --------------------------------------------- */
  /* EMPTY STATE */
  /* --------------------------------------------- */
  if (!messageId) {
    return (
      <div className="flex h-full flex-col items-center justify-center text-[var(--tm-text-secondary)] bg-[var(--tm-bg)]">
        <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[var(--tm-surface)] text-4xl shadow-inner border border-[var(--tm-border)]">
          📬
        </div>
        <p className="mt-4 text-lg font-medium text-[var(--tm-text-secondary)]">No Email Selected</p>
        <p className="mt-2 text-sm text-[var(--tm-text-secondary)]">Select an email from your inbox to view the security analysis.</p>
      </div>
    );
  }

  /* --------------------------------------------- */
  /* LOADING */
  /* --------------------------------------------- */
  if (loading) {
    return <LoadingSkeleton />;
  }

  /* --------------------------------------------- */
  /* ERROR */
  /* --------------------------------------------- */
  if (error) {
    return (
      <div className="p-8 text-red-400 text-center mt-10">
        <div className="text-4xl mb-4">⚠️</div>
        {error}
      </div>
    );
  }

  if (!message) {
    return null;
  }

  const analysis = message.analysis || {};
  const decision = analysis.decision || {};
  const authentication = analysis.authentication || {};
  const content = analysis.content || {};
  const urlAnalysis = analysis.url || {};
  const whois = analysis.whois || [];
  const attachment = analysis.attachment || {};
  const trust = analysis.trust || {};
  const reasoning = analysis.reasoning || {};
  const intelligence = analysis.intelligence || {};
  const urlPageIntelligence = analysis.url_page_intelligence || {};

  return (
    <div className="min-h-full w-full max-w-[1200px] mx-auto space-y-6 p-8">
      <EmailHeaders message={message} />
      <ThreatOverview decision={decision} />
      <AuthenticationCard authentication={authentication} />
      <ContentAnalysisCard content={content} />
      <URLIntelligence urlAnalysis={urlAnalysis} urlPageIntelligence={urlPageIntelligence} />
      <WhoisAnalysis whois={whois} />
      <AttachmentAnalysis attachmentData={attachment} rawAttachments={message.attachments} />
      <TrustAnalysis trust={trust} />
      <SecurityReasoning reasoning={reasoning} ai={analysis.ai} explanation={analysis.explanation} />
      <FinalDecision decision={decision} />
      <AnalystExplanation messageId={message.id} decision={decision} sender={message.sender} />
      <IntelligenceCard
        intelligence={intelligence}
        messageId={message.id}
        automatedVerdict={decision.verdict}
      />
      {analysis?.ai?.adaptive && (
        <AdaptiveIntelligence adaptive={analysis.ai.adaptive} />
      )}
      <EmailContent body={message.body} htmlBody={message.html_body} />
      <TechnicalHeaders headers={message.headers} />
    </div>
  );
}

export default EmailDetail;
