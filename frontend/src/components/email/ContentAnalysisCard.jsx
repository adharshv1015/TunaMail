import React from "react";
import SectionHeader from "../common/SectionHeader";

function BooleanItem({ label, value }) {
  const getStatusColor = () => {
    if (value) return "text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/20";
    return "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  };

  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-4 text-center">
      <span className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">{label}</span>
      <div className={`flex items-center justify-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${getStatusColor()}`}>
        {value ? "⚠ Detected" : "✓ Not detected"}
      </div>
    </div>
  );
}

function ContentAnalysisCard({ content }) {
  const data = content || {};

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <SectionHeader icon="🧠" title="Content Analysis" subtitle="Behavioral and linguistic indicators" />

      <div className="mt-5 grid grid-cols-2 gap-3 xl:grid-cols-5">
        <BooleanItem label="Urgency" value={data.urgency} />
        <BooleanItem label="Credential Req." value={data.credential_request} />
        <BooleanItem label="Financial Req." value={data.financial_request} />
        <BooleanItem label="Impersonation" value={data.impersonation} />
        <BooleanItem label="Threat Language" value={data.threat_language} />
      </div>

      {data.risk_score !== undefined && (
        <div className="mt-5 flex items-center justify-between text-xs text-[var(--tm-text-secondary)] bg-[var(--tm-surface-secondary)] p-3 rounded-lg border border-[var(--tm-border)]">
          <span>Content risk contribution</span>
          <span className="font-semibold text-[var(--tm-text)]">{data.risk_score} / 100</span>
        </div>
      )}
    </section>
  );
}

export default ContentAnalysisCard;
