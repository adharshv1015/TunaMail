import React from "react";
import SectionHeader from "../common/SectionHeader";
import EmptyState from "../common/EmptyState";

function IndicatorBadge({ label, isSuspicious }) {
  if (!isSuspicious && label !== "Normal") return null;
  
  if (isSuspicious) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20">
        {label}
      </span>
    );
  }

  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20">
      NO FLAGS
    </span>
  );
}

function UrlCard({ item }) {
  const hasRisk = item.ip_based || item.shortener || item.obfuscated || item.punycode || item.suspicious_port || (item.keywords && item.keywords.length > 0);

  return (
    <div className={`flex flex-col gap-3 rounded-[12px] border bg-[var(--tm-surface-secondary)] p-4 ${hasRisk ? "border-orange-500/30" : "border-[var(--tm-border)]"}`}>
      <div className="flex flex-col">
        <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">URL</div>
        <div className="mt-1 break-all font-mono text-[13px] text-[var(--tm-text)]" style={{ wordBreak: "break-word" }}>{item.url}</div>
      </div>
      
      <div className="flex flex-col md:flex-row gap-4 mt-2">
        <div className="flex-1">
          <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider">Domain</div>
          <div className="mt-1 font-mono text-[13px] text-[var(--tm-accent)]">{item.domain || "Unknown"}</div>
        </div>
        
        <div className="flex-1">
          <div className="text-[11px] font-bold text-[var(--tm-text-secondary)] uppercase tracking-wider mb-1.5">Intelligence Properties</div>
          <div className="flex flex-wrap gap-2">
            {!hasRisk && <IndicatorBadge label="Normal" isSuspicious={false} />}
            <IndicatorBadge label="IP-Based" isSuspicious={item.ip_based} />
            <IndicatorBadge label="Shortener" isSuspicious={item.shortener} />
            <IndicatorBadge label="Obfuscated" isSuspicious={item.obfuscated} />
            <IndicatorBadge label="Punycode" isSuspicious={item.punycode} />
            <IndicatorBadge label="Suspicious Port" isSuspicious={item.suspicious_port} />
            {item.keywords && item.keywords.length > 0 && (
              <span className="inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20">
                KEYWORDS: {item.keywords.join(", ")}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function URLIntelligence({ urlAnalysis }) {
  const data = urlAnalysis || {};
  const analyzedUrls = data.analysis || [];

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <SectionHeader icon="🔗" title="URL Intelligence" subtitle={`${analyzedUrls.length} URL(s) analyzed in the email body`} />
      
      {analyzedUrls.length === 0 ? (
        <EmptyState icon="✓" message="No URLs detected in this email." />
      ) : (
        <div className="mt-5 space-y-4">
          {analyzedUrls.map((item, index) => (
            <UrlCard key={`${item.url}-${index}`} item={item} />
          ))}
        </div>
      )}
    </section>
  );
}

export default URLIntelligence;
