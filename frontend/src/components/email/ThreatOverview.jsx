import React from "react";
import VerdictBadge from "../common/VerdictBadge";

function ThreatOverview({ decision }) {
  const riskScore = decision.risk_score ?? 0;
  const confidence = decision.confidence ?? 0;
  const verdict = decision.verdict || "SAFE";
  const recommendation = decision.recommendation || "No immediate threats detected.";

  const getRiskBarStyle = () => {
    switch (verdict) {
      case "PHISHING":
        return "bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]";
      case "HIGH RISK":
        return "bg-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.5)]";
      case "SUSPICIOUS":
        return "bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]";
      case "LOW RISK":
        return "bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]";
      default:
        return "bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]";
    }
  };

  const getRiskIcon = () => {
    switch (verdict) {
      case "PHISHING": return "🚨";
      case "HIGH RISK": return "⚠️";
      case "SUSPICIOUS": return "⚠️";
      case "LOW RISK": return "ℹ️";
      default: return "✓";
    }
  };

  const barStyle = getRiskBarStyle();
  const icon = getRiskIcon();

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-6 md:p-8 shadow-[0_8px_30px_rgba(15,23,42,0.06)] dark:shadow-[0_8px_30px_rgba(0,0,0,0.25)]">
      <div className="mb-8 flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-[var(--tm-text)]">Threat Overview</h2>
          <p className="mt-1 text-[13px] text-[var(--tm-text-secondary)]">Primary security intelligence assessment</p>
        </div>
        <VerdictBadge verdict={verdict} className="px-3 py-1.5 text-xs" />
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* RISK SCORE */}
        <div className="rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-6">
          <div className="flex flex-col items-center justify-center py-4">
            <span className="text-[12px] font-bold tracking-wider text-[var(--tm-text-secondary)] uppercase">Risk Score</span>
            <div className="mt-2 flex items-baseline">
              <span className="text-6xl font-black text-[var(--tm-text)] tracking-tighter">
                {riskScore}
              </span>
              <span className="ml-1 text-xl font-bold text-[var(--tm-text-muted)]">/100</span>
            </div>
          </div>
          
          <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-500 ease-out ${barStyle}`}
              style={{ width: `${Math.min(riskScore, 100)}%` }}
            />
          </div>
          <div className="mt-3 flex justify-between text-[11px] font-semibold text-[var(--tm-text-muted)] uppercase tracking-wider">
            <span>Safe</span>
            <span>Critical</span>
          </div>
        </div>

        {/* CONFIDENCE & RECOMMENDATION */}
        <div className="flex flex-col gap-6">
          {/* CONFIDENCE */}
          <div className="rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-6">
            <div className="flex items-center justify-between mb-4">
              <span className="text-[12px] font-bold tracking-wider text-[var(--tm-text-secondary)] uppercase">Confidence</span>
              <span className="text-2xl font-bold text-[var(--tm-text)]">{confidence}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
              <div
                className="h-full rounded-full bg-[var(--tm-accent)] transition-all duration-500 ease-out shadow-[0_0_10px_rgba(99,102,241,0.5)]"
                style={{ width: `${Math.min(confidence, 100)}%` }}
              />
            </div>
          </div>

          {/* RECOMMENDATION */}
          <div className="flex-1 rounded-[14px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5 flex gap-4">
            <div className="text-2xl pt-0.5">{icon}</div>
            <div>
              <h3 className="text-[13px] font-bold text-[var(--tm-text)]">Security Recommendation</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--tm-text-secondary)]">{recommendation}</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ThreatOverview;
