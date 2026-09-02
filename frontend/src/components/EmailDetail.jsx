import React, { useEffect, useState } from "react";
import { getMessage, streamMessage } from "../api/api";
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
import AnalysisProgressScreen from "./email/AnalysisProgressScreen";

function EmailDetail({ messageId, messageMeta, onBack, resultSet = [], currentIndex = -1, onNavigate, onMessageAnalyzed }) {
  console.log("EMAIL DETAIL RENDER:", {
    messageId,
    currentIndex,
    resultSetLength: resultSet.length,
  });

  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [progressStep, setProgressStep] = useState("Preparing analysis");
  const [progressDetail, setProgressDetail] = useState("");

  useEffect(() => {
    // 1. Abort previous request (handled by cleanup)
    // 2. Clear previous message
    setMessage(null);
    // 3. Clear previous error
    setError("");
    // 4. Reset progress
    setProgress(0);
    setProgressStep("Preparing analysis");
    setProgressDetail("");

    if (!messageId) {
      return;
    }

    if (!messageMeta) {
      setError("Email metadata is unavailable. Please return to the inbox and try again.");
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    const { signal } = controller;
    setLoading(true);

    const loadMessage = async () => {
      try {
        if (messageMeta.analysis_status === "ANALYZED") {
          console.log("Loading cached message:", messageId);
          const data = await getMessage(messageId, { signal });
          if (!signal.aborted) {
            setMessage(data);
          }
        } else if (messageMeta.analysis_status === "UNANALYZED") {
          setProgressDetail("Starting security analysis...");
          console.log("Streaming analysis for message:", messageId);

          await streamMessage(messageId, {
            signal,
            onProgress: (event) => {
              if (signal.aborted) return;
              setProgress(event.progress ?? 0);
              setProgressStep(event.step || "Analyzing email");
              setProgressDetail(event.detail || "");
            },
            onResult: (data) => {
              if (signal.aborted) return;
              setProgress(100);
              setProgressStep("Analysis complete");
              setProgressDetail("Security analysis completed successfully.");
              setMessage(data);
              if (data && onMessageAnalyzed) {
                onMessageAnalyzed(messageId, data);
              }
            },
            onError: (event) => {
              if (signal.aborted) return;
              console.error("Streaming analysis error:", event);
              setError(event.message || "Failed to load email analysis.");
            },
          });
        } else {
          setError("Unknown email analysis status.");
          setLoading(false);
        }
      } catch (err) {
        if (err.name === "AbortError") {
          console.log("Analysis aborted for message:", messageId);
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
  }, [messageId, messageMeta, onMessageAnalyzed]);

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
    if (messageMeta?.analysis_status === "UNANALYZED" || progress > 0) {
      return (
        <AnalysisProgressScreen
          progress={progress}
          step={progressStep}
          detail={progressDetail}
        />
      );
    }

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
    <div className="min-h-full w-full max-w-[1200px] mx-auto space-y-4 md:space-y-6 p-4 md:p-6 lg:p-8">
      {onBack && (
        <div className="lg:hidden sticky top-0 z-10 -mx-4 md:-mx-6 px-4 md:px-6 py-3 bg-[var(--tm-bg)]/95 backdrop-blur border-b border-[var(--tm-border)] mb-4 md:mb-6">
          <button
            onClick={onBack}
            className="flex items-center gap-2 text-sm font-medium text-[var(--tm-accent)]"
          >
            <span aria-hidden="true">←</span>
            Back to Inbox
          </button>
        </div>
      )}

      {/* Scoped Prev / Next within current result set */}
      {resultSet.length > 1 && currentIndex !== -1 && (
        <div className="flex items-center justify-between rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] px-4 py-2.5">
          <button
            onClick={() => onNavigate?.(currentIndex - 1)}
            disabled={currentIndex <= 0}
            className="flex items-center gap-1.5 text-xs font-semibold text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>
          <span className="text-[11px] text-[var(--tm-text-muted)]">
            {currentIndex + 1} / {resultSet.length}
          </span>
          <button
            onClick={() => onNavigate?.(currentIndex + 1)}
            disabled={currentIndex >= resultSet.length - 1}
            className="flex items-center gap-1.5 text-xs font-semibold text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
      <EmailHeaders message={message} />
      <ThreatOverview decision={decision} />
      <AuthenticationCard authentication={authentication} />
      <ContentAnalysisCard content={content} />
      <URLIntelligence urlAnalysis={urlAnalysis} urlPageIntelligence={urlPageIntelligence} />
      <WhoisAnalysis whois={whois} />
      <AttachmentAnalysis
        attachmentData={attachment}
        rawAttachments={message.attachments}
        messageId={message.id}
        onAnalysisUpdated={(newDecision) => {
          if (!message) return;
          const updatedMessage = {
            ...message,
            decision: newDecision,
            analysis: {
              ...message.analysis,
              decision: newDecision
            }
          };
          setMessage(updatedMessage);
          if (onMessageAnalyzed) {
            onMessageAnalyzed(message.id, updatedMessage);
          }
        }}
      />
      <TrustAnalysis trust={trust} />
      <SecurityReasoning reasoning={reasoning} ai={analysis.ai} explanation={analysis.explanation} />
      <FinalDecision decision={decision} />
      <AnalystExplanation messageId={message.id} decision={decision} explanation={analysis.explanation || decision.explanation} sender={message.sender} />
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
