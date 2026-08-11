import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";

function TechnicalHeaders({ headers }) {
  const [showRaw, setShowRaw] = useState(false);
  const rawHeaders = headers || {};
  const headerKeys = Object.keys(rawHeaders);

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <SectionHeader icon="📋" title="Technical Headers" subtitle="Raw SMTP transport headers" />
        <button 
          onClick={() => setShowRaw(!showRaw)}
          className="rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] px-4 py-2 text-xs font-semibold text-[var(--tm-text-secondary)] hover:bg-[var(--tm-primary)]/5 hover:text-[var(--tm-primary)] hover:border-[var(--tm-primary)]/30 transition-all cursor-pointer"
        >
          {showRaw ? "Hide headers" : "Show headers"}
        </button>
      </div>

      {showRaw && (
        <div className="mt-5 rounded-[12px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-4 max-h-[300px] overflow-y-auto custom-scrollbar">
          {headerKeys.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
              {headerKeys.map((key, idx) => (
                <div key={idx} className="text-[11px] break-inside-avoid bg-[var(--tm-surface)] p-3 rounded-lg border border-[var(--tm-border)]">
                  <span className="font-bold text-[var(--tm-text)] block mb-1 uppercase tracking-wider opacity-80">{key}</span>
                  <span className="text-[var(--tm-text-secondary)] break-all block">{rawHeaders[key]}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-[var(--tm-text-secondary)]">No raw headers available.</div>
          )}
        </div>
      )}
    </section>
  );
}

export default TechnicalHeaders;
