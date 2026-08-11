import React from "react";
import SectionHeader from "../common/SectionHeader";

function formatEvidence(text) {
  if (!text) return "";

  // 1. Translate technical jargon to simple terms
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

  // 2. Extract and nicely format URLs so they don't flood the UI
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
          return cleanPart ? <span key={i} className="font-semibold">{cleanPart}</span> : null;
        })}
      </div>
    );
  }

  return <span className="font-semibold">{formatted}</span>;
}

function EvidenceColumn({ title, items, color }) {
  const colors = {
    red: "border-red-500/20 bg-red-500/10 text-red-600 dark:text-red-400",
    orange: "border-orange-500/20 bg-orange-500/10 text-orange-600 dark:text-orange-400",
    blue: "border-blue-500/20 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  };

  const getIcon = () => {
    if (color === "red" || color === "orange") return "⚠️";
    return "ℹ️";
  };

  const colorClass = colors[color] || colors.blue;
  const icon = getIcon();

  return (
    <div className="rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[12px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">{title}</h3>
        <span className="text-[11px] font-bold text-[var(--tm-text-muted)]">{items?.length || 0}</span>
      </div>
      
      {items?.length > 0 ? (
        <div className="space-y-3">
          {items.map((item, index) => (
            <div key={index} className={`flex gap-2.5 rounded-[10px] border p-3.5 text-[12px] leading-relaxed break-all ${colorClass}`}>
              <span className="text-sm shrink-0">{icon}</span>
              <div className="pt-0.5">{formatEvidence(item)}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-[12px] font-medium text-[var(--tm-text-secondary)] italic">No evidence detected.</div>
      )}
    </div>
  );
}

function SecurityReasoning({ reasoning, ai }) {
  const data = reasoning || {};

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <SectionHeader icon="🧩" title="Analysis Evidence" subtitle="Evidence accumulated by the Analysis & Risk Engine" />
      
      {ai && (
        <div className="mt-4 flex flex-wrap gap-2">
          {ai.brand_intelligence?.some(b => b.impersonation_risk) && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-600 dark:text-red-400 border border-red-500/20">
              🎭 Brand Impersonation Detected
            </span>
          )}
          {ai.adversarial?.length > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-orange-500/10 px-3 py-1 text-xs font-semibold text-orange-600 dark:text-orange-400 border border-orange-500/20">
              🛡️ Adversarial Tactics Detected
            </span>
          )}
          {ai.contradictions_engine?.contradiction_detected && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-yellow-500/10 px-3 py-1 text-xs font-semibold text-yellow-600 dark:text-yellow-400 border border-yellow-500/20">
              ⚖️ Evidence Contradictions Found
            </span>
          )}
          {ai.homoglyph?.length > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/10 px-3 py-1 text-xs font-semibold text-purple-600 dark:text-purple-400 border border-purple-500/20">
              🔤 Homoglyph/Lookalike URL
            </span>
          )}
          {ai.sender_reputation && ai.sender_reputation.reputation !== "UNKNOWN" && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-indigo-500/10 px-3 py-1 text-xs font-semibold text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
              👤 Reputation: {ai.sender_reputation.reputation.replace("_", " ")}
            </span>
          )}
          {ai.campaign?.length > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-teal-500/10 px-3 py-1 text-xs font-semibold text-teal-600 dark:text-teal-400 border border-teal-500/20">
              📊 Campaign Activity Detected
            </span>
          )}
          {ai.behavioral?.length > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-pink-500/10 px-3 py-1 text-xs font-semibold text-pink-600 dark:text-pink-400 border border-pink-500/20">
              🔄 Sender Behavior Change
            </span>
          )}
        </div>
      )}
      
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <EvidenceColumn title="Technical" items={data.technical} color="red" />
        <EvidenceColumn title="Behavioral" items={data.behavioral} color="orange" />
        <EvidenceColumn title="Network" items={data.network} color="blue" />
      </div>
    </section>
  );
}

export default SecurityReasoning;
