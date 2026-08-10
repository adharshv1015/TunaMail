import React, { useState } from "react";
import SectionHeader from "../common/SectionHeader";
import VerdictBadge from "../common/VerdictBadge";

function EmailHeaders({ message }) {
  const [showRaw, setShowRaw] = useState(false);
  
  const analysis = message.analysis || {};
  const decision = analysis.decision || {};
  const verdict = decision.verdict || "SAFE";

  const rawHeaders = message.headers || {};
  const headerKeys = Object.keys(rawHeaders);

  return (
    <section className="space-y-6">
      {/* Primary Header Card */}
      <div className="rounded-2xl border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex-1 space-y-4">
            <h1 className="text-2xl font-bold text-[var(--tm-text)] tracking-tight leading-tight">
              {message.subject || "(No subject)"}
            </h1>
            
            <div className="flex flex-col gap-2 text-[14px]">
              <div className="flex items-start">
                <span className="w-16 font-semibold text-[var(--tm-text-secondary)]">From</span>
                <span className="flex-1 font-medium text-[var(--tm-text)] break-all">{message.from}</span>
              </div>
              <div className="flex items-start">
                <span className="w-16 font-semibold text-[var(--tm-text-secondary)]">To</span>
                <span className="flex-1 text-[var(--tm-text)] break-all">{message.to}</span>
              </div>
              {message.date && (
                <div className="flex items-start">
                  <span className="w-16 font-semibold text-[var(--tm-text-secondary)]">Date</span>
                  <span className="flex-1 text-[var(--tm-text)]">{message.date}</span>
                </div>
              )}
            </div>
          </div>

          <div className="shrink-0 pt-1 lg:pt-0">
            <VerdictBadge verdict={verdict} className="px-4 py-1.5 text-sm" />
          </div>
        </div>
      </div>

      {/* Raw Technical Headers */}
      <div className="rounded-2xl border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 shadow-sm">
        <div className="flex items-center justify-between">
          <SectionHeader icon="📋" title="Technical Headers" subtitle="Raw SMTP transport headers" />
          <button 
            onClick={() => setShowRaw(!showRaw)}
            className="rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] px-4 py-2 text-xs font-semibold text-[var(--tm-text-secondary)] hover:bg-[var(--tm-accent)]/5 hover:text-[var(--tm-accent)] hover:border-[var(--tm-accent)]/30 transition-all cursor-pointer"
          >
            {showRaw ? "Hide headers" : "Show headers"}
          </button>
        </div>

        {showRaw && (
          <div className="mt-5 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-4 max-h-[300px] overflow-y-auto custom-scrollbar">
            {headerKeys.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {headerKeys.map((key, idx) => (
                  <div key={idx} className="text-xs break-inside-avoid">
                    <span className="font-semibold text-[var(--tm-text)] block mb-1">{key}</span>
                    <span className="text-[var(--tm-text-secondary)] break-all block">{rawHeaders[key]}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-[var(--tm-text-secondary)]">No raw headers available.</div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export default EmailHeaders;
