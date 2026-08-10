import React from "react";
import SectionHeader from "../common/SectionHeader";
import EmptyState from "../common/EmptyState";

function WhoisField({ label, value }) {
  return (
    <div className="rounded-[10px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-3">
      <div className="text-[10px] font-bold tracking-wider text-[var(--tm-text-secondary)] uppercase">{label}</div>
      <div className="mt-1 truncate text-[13px] font-medium text-[var(--tm-text)]">{value || "Unknown"}</div>
    </div>
  );
}

function WhoisCard({ item }) {
  const isSuspicious = item.age_days !== undefined && item.age_days < 30;
  
  const hasError = !!item.error;
  const isUnavailable = hasError && item.error.toLowerCase().includes("unavailable");

  return (
    <div className={`rounded-[14px] border bg-[var(--tm-surface-secondary)] p-5 ${isSuspicious ? "border-orange-500/30" : "border-[var(--tm-border)]"}`}>
      <div className="flex items-center justify-between">
        <div className="text-[14px] font-bold text-[var(--tm-text)]">{item.domain}</div>
        {isSuspicious && (
          <div className="rounded border border-orange-500/20 bg-orange-500/10 px-2 py-0.5 text-[10px] font-bold tracking-wider text-orange-600 dark:text-orange-400 uppercase">
            NEW DOMAIN
          </div>
        )}
      </div>

      {!hasError ? (
        <div className="mt-4 grid grid-cols-2 gap-3">
          <WhoisField label="Age (Days)" value={item.age_days} />
          <WhoisField label="Registrar" value={item.registrar} />
          <WhoisField label="Creation Date" value={item.creation_date} />
          <WhoisField label="Country" value={item.country} />
        </div>
      ) : (
        <div className={`mt-4 flex gap-3 rounded-[10px] border p-4 ${isUnavailable ? "border-blue-500/20 bg-blue-500/10 text-blue-600 dark:text-blue-400" : "border-orange-500/20 bg-orange-500/10 text-orange-600 dark:text-orange-400"}`}>
          <div className="text-xl shrink-0 mt-0.5">{isUnavailable ? "ℹ️" : "⚠️"}</div>
          <div>
            <div className="text-[12px] font-bold uppercase tracking-wider">{isUnavailable ? "WHOIS lookup unavailable" : "WHOIS Error"}</div>
            <p className="mt-1 break-all text-[13px] leading-relaxed opacity-90">{isUnavailable ? "Unable to retrieve registration information for this domain." : item.error}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function WhoisAnalysis({ whois }) {
  const data = whois || [];

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <SectionHeader icon="🌐" title="WHOIS Analysis" subtitle="Domain registration intelligence" />
      
      {data.length === 0 ? (
        <EmptyState icon="✓" message="No WHOIS records available." />
      ) : (
        <div className="mt-5 grid grid-cols-1 gap-4 xl:grid-cols-2">
          {data.map((item, index) => (
            <WhoisCard key={`${item.domain}-${index}`} item={item} />
          ))}
        </div>
      )}
    </section>
  );
}

export default WhoisAnalysis;
