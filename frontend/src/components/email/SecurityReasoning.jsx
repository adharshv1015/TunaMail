import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";

function formatEvidence(text) {
  if (!text) return "";

  const translations = [
    { match: /Obfuscated URL detected/i, replace: "Suspicious or hidden web link found" },
    { match: /Possible impersonation/i, replace: "Sender might be pretending to be someone else" },
    { match: /SPF fail/i, replace: "Failed sender identity check (SPF)" },
    { match: /DKIM fail/i, replace: "Failed email tampering check (DKIM)" },
    { match: /DMARC fail/i, replace: "Failed domain security check (DMARC)" },
    { match: /Suspicious attachment/i, replace: "Potentially dangerous file attached" },
  ];

  let formatted = text;
  translations.forEach((t) => {
    formatted = formatted.replace(t.match, t.replace);
  });

  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts = formatted.split(urlRegex);

  if (parts.length > 1) {
    return (
      <div className="flex flex-col gap-1.5 mt-1">
        {parts.map((part, i) => {
          if (part.match(urlRegex)) {
            try {
              const url = new URL(part);
              return (
                <div
                  key={i}
                  className="truncate rounded bg-[var(--tm-surface)] px-2 py-1.5 font-mono text-[10px] text-[var(--tm-text-secondary)] border border-[var(--tm-border)]"
                  title={part}
                >
                  🔗 {url.hostname}
                </div>
              );
            } catch (e) {
              return (
                <div key={i} className="truncate rounded bg-[var(--tm-surface)] px-2 py-1.5 font-mono text-[10px] text-[var(--tm-text-secondary)] border border-[var(--tm-border)]" title={part}>
                  {part}
                </div>
              );
            }
          }
          const cleanPart = part.replace(/:\s*$/, "").trim();
          return cleanPart ? <span key={i} className="font-medium">{cleanPart}</span> : null;
        })}
      </div>
    );
  }

  return <span className="font-medium">{formatted}</span>;
}

function Accordion({ title, items, color, defaultOpen = false, icon = "ℹ️" }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  if (!items || items.length === 0) return null;

  const colors = {
    red:    "border-red-500/20 bg-red-500/5 hover:bg-red-500/10 text-red-700 dark:text-red-400",
    green:  "border-green-500/20 bg-green-500/5 hover:bg-green-500/10 text-green-700 dark:text-green-400",
    orange: "border-orange-500/20 bg-orange-500/5 hover:bg-orange-500/10 text-orange-700 dark:text-orange-400",
    blue:   "border-blue-500/20 bg-blue-500/5 hover:bg-blue-500/10 text-blue-700 dark:text-blue-400",
    teal:   "border-teal-500/20 bg-teal-500/5 hover:bg-teal-500/10 text-teal-700 dark:text-teal-400",
    purple: "border-purple-500/20 bg-purple-500/5 hover:bg-purple-500/10 text-purple-700 dark:text-purple-400",
    gray:   "border-gray-500/20 bg-gray-500/5 hover:bg-gray-500/10 text-gray-700 dark:text-gray-400",
  };

  const contentColors = {
    red:    "bg-red-500/5 border-red-500/10 text-red-600 dark:text-red-400",
    green:  "bg-green-500/5 border-green-500/10 text-green-600 dark:text-green-400",
    orange: "bg-orange-500/5 border-orange-500/10 text-orange-600 dark:text-orange-400",
    blue:   "bg-blue-500/5 border-blue-500/10 text-blue-600 dark:text-blue-400",
    teal:   "bg-teal-500/5 border-teal-500/10 text-teal-600 dark:text-teal-400",
    purple: "bg-purple-500/5 border-purple-500/10 text-purple-600 dark:text-purple-400",
    gray:   "bg-gray-500/5 border-gray-500/10 text-gray-600 dark:text-gray-400",
  };

  const headerColor = colors[color] || colors.blue;
  const bodyColor   = contentColors[color] || contentColors.blue;

  return (
    <div className="mb-3 rounded-[12px] border border-[var(--tm-border)] overflow-hidden bg-[var(--tm-surface-secondary)]">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between p-3.5 text-left transition-colors ${headerColor}`}
      >
        <div className="flex items-center gap-2">
          <span>{icon}</span>
          <span className="font-semibold text-[13px]">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-bold opacity-70 px-2 py-0.5 rounded-full bg-black/5 dark:bg-white/10">
            {items.length} item{items.length !== 1 ? "s" : ""}
          </span>
          <span className={`transform transition-transform ${isOpen ? "rotate-180" : ""}`}>▼</span>
        </div>
      </button>

      {isOpen && (
        <div className="p-4 space-y-3 border-t border-[var(--tm-border)] bg-[var(--tm-surface)]">
          {items.map((item, index) => (
            <div
              key={index}
              className={`flex gap-3 rounded-[8px] border p-3 text-[12px] leading-relaxed break-words [overflow-wrap:anywhere] ${bodyColor}`}
            >
              <div className="flex-1 min-w-0 space-y-1">
                <div className="font-bold text-[13px]">{item.title}</div>
                <div className="opacity-90">{formatEvidence(item.explanation)}</div>
                {item.source && (
                  <div className="text-[10px] font-mono opacity-60 pt-1">
                    Source: {item.source}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Small agreement summary row */
function AgreementSummary({ agreement }) {
  if (!agreement) return null;
  const { positive_sources, negative_sources, contradictory_sources, independent_sources } = agreement;

  return (
    <div className="flex flex-wrap gap-3 my-4">
      {positive_sources > 0 && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-green-500/10 text-green-700 dark:text-green-400 border border-green-500/20">
          ✓ {positive_sources} positive signal{positive_sources !== 1 ? "s" : ""}
        </div>
      )}
      {negative_sources > 0 && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-red-500/10 text-red-700 dark:text-red-400 border border-red-500/20">
          ⚠ {negative_sources} negative signal{negative_sources !== 1 ? "s" : ""}
        </div>
      )}
      {contradictory_sources > 0 && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-orange-500/10 text-orange-700 dark:text-orange-400 border border-orange-500/20">
          ⚖️ {contradictory_sources} contradiction{contradictory_sources !== 1 ? "s" : ""}
        </div>
      )}
      {independent_sources > 0 && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-blue-500/10 text-blue-700 dark:text-blue-400 border border-blue-500/20">
          🔬 {independent_sources} independent source{independent_sources !== 1 ? "s" : ""}
        </div>
      )}
    </div>
  );
}

function SecurityReasoning({ reasoning, ai, explanation }) {
  // Stage 13: explanation engine output with groups
  if (explanation && explanation.groups) {
    const {
      groups,
      primary_reason,
      final_reason,
      confidence_explanation,
      agreement,
    } = explanation;

    const hasNegative     = (groups.NEGATIVE_EVIDENCE?.length ?? 0) > 0;
    const hasPositive     = (groups.POSITIVE_EVIDENCE?.length ?? 0) > 0;
    const hasContradictions = (groups.CONTRADICTIONS?.length ?? 0) > 0;
    const hasContext      = (groups.CONTEXT_LIMITATIONS?.length ?? 0) > 0;
    const hasBehavioral   = (groups.BEHAVIORAL_FINDINGS?.length ?? 0) > 0;
    const hasURL          = (groups.URL_FINDINGS?.length ?? 0) > 0;
    const hasAuth         = (groups.AUTHENTICATION_FINDINGS?.length ?? 0) > 0;
    const hasBrand        = (groups.BRAND_FINDINGS?.length ?? 0) > 0;
    const hasSupporting   = (groups.SUPPORTING_EVIDENCE?.length ?? 0) > 0;

    return (
      <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm mt-6">
        <SectionHeader
          icon="🧠"
          title="Decision Explanation"
          subtitle="Evidence-based reasoning for the final verdict"
        />

        <div className="mt-5 space-y-4">
          {/* Primary Reason */}
          {primary_reason && (
            <div className="rounded-[12px] bg-blue-500/10 border border-blue-500/20 p-4">
              <h3 className="text-[11px] font-bold text-blue-600 dark:text-blue-400 uppercase tracking-wider mb-1">
                Primary Detection
              </h3>
              <p className="font-semibold text-blue-800 dark:text-blue-300 text-[14px]">
                {primary_reason}
              </p>
            </div>
          )}

          {/* Agreement summary chips */}
          <AgreementSummary agreement={agreement} />

          {/* Evidence Accordions */}
          <div className="space-y-1">
            <Accordion
              title="Negative Evidence"
              items={groups.NEGATIVE_EVIDENCE}
              color="red"
              icon="⚠"
              defaultOpen={hasNegative}
            />
            <Accordion
              title="Positive Evidence"
              items={groups.POSITIVE_EVIDENCE}
              color="green"
              icon="✓"
              defaultOpen={hasPositive && !hasNegative}
            />
            <Accordion
              title="Contradictions"
              items={groups.CONTRADICTIONS}
              color="orange"
              icon="⚖️"
              defaultOpen={hasContradictions}
            />
            <Accordion
              title="Brand Intelligence"
              items={groups.BRAND_FINDINGS}
              color="purple"
              icon="🏷️"
              defaultOpen={hasBrand}
            />
            <Accordion
              title="Behavioral Findings"
              items={groups.BEHAVIORAL_FINDINGS}
              color="orange"
              icon="🔄"
              defaultOpen={hasBehavioral && !hasNegative}
            />
            <Accordion
              title="URL Findings"
              items={groups.URL_FINDINGS}
              color="blue"
              icon="🔗"
            />
            <Accordion
              title="Authentication Findings"
              items={groups.AUTHENTICATION_FINDINGS}
              color="teal"
              icon="🔐"
            />
            <Accordion
              title="Context Limitations"
              items={groups.CONTEXT_LIMITATIONS}
              color="gray"
              icon="ℹ️"
              defaultOpen={hasContext && !hasNegative && !hasPositive}
            />
            <Accordion
              title="Supporting Evidence"
              items={groups.SUPPORTING_EVIDENCE}
              color="gray"
              icon="📋"
            />
          </div>

          {/* Confidence explanation */}
          {confidence_explanation && (
            <div className="rounded-[10px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] px-4 py-3">
              <h3 className="text-[10px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-1">
                Confidence Assessment
              </h3>
              <p className="text-[12px] text-[var(--tm-text)] leading-relaxed">
                {confidence_explanation}
              </p>
            </div>
          )}

          {/* Final Reason */}
          {final_reason && (
            <div className="pt-4 border-t border-[var(--tm-border)]">
              <h3 className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-2">
                Final Reason
              </h3>
              <p className="text-[13px] text-[var(--tm-text)] leading-relaxed font-medium">
                {final_reason}
              </p>
            </div>
          )}
        </div>
      </section>
    );
  }

  // Fallback for pre-Stage 13 reasoning data
  const data = reasoning || {};

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm mt-6">
      <SectionHeader
        icon="🧩"
        title="Analysis Evidence"
        subtitle="Evidence accumulated by the Analysis & Risk Engine"
      />
      <div className="mt-5 text-sm text-[var(--tm-text-secondary)] italic">
        Legacy reasoning view. Upgrade to Stage 13 for detailed evidence explanations.
      </div>
    </section>
  );
}

export default SecurityReasoning;
