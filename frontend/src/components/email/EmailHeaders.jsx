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
      <div className="rounded-2xl border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex-1 min-w-0 space-y-4">
            <h1 className="text-2xl font-bold text-[var(--tm-text)] tracking-tight leading-tight break-words [overflow-wrap:anywhere]">
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

    </section>
  );
}

export default EmailHeaders;
