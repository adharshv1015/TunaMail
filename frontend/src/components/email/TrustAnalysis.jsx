import React from "react";
import SectionHeader from "../common/SectionHeader";

function TrustAnalysis({ trust }) {
  const data = trust || {};
  const trustScore = data.trust_score ?? 0;

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader icon="🔐" title="Trust Analysis" subtitle="Sender and organization trust assessment" />
      
      <div className="mt-5 rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-6">
        <div className="flex flex-col items-center justify-center border-b border-[var(--tm-border)] pb-6 mb-6">
          <span className="text-[12px] font-bold tracking-wider text-[var(--tm-text-secondary)] uppercase">Trust Score</span>
          <div className="mt-2 flex items-baseline">
            <span className="text-5xl font-black text-[var(--tm-text)] tracking-tighter">{trustScore}</span>
            <span className="ml-1 text-lg font-bold text-[var(--tm-text-muted)]">/100</span>
          </div>
        </div>
        
        {data.evidence?.length > 0 ? (
          <div className="space-y-3">
            <h4 className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-2">Trust Factors</h4>
            {data.evidence.map((item, index) => (
              <div key={index} className="flex gap-2 text-[13px] leading-relaxed text-[var(--tm-text)] bg-[var(--tm-surface)] p-3 rounded-[10px] border border-[var(--tm-border)]">
                <span className="shrink-0 text-[var(--tm-accent)]">✓</span>
                <span className="break-words [overflow-wrap:anywhere] min-w-0">{item}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[13px] font-medium text-[var(--tm-text-secondary)] italic text-center">No additional trust indicators reported.</p>
        )}
      </div>
    </section>
  );
}

export default TrustAnalysis;
