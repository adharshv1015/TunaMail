import React from "react";
import SectionHeader from "../common/SectionHeader";

function FinalDecision({ decision }) {
  const data = decision || {};
  const verdict = data.verdict || "UNKNOWN";
  
  const getStyles = () => {
    switch (verdict) {
      case "PHISHING":
        return "bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400";
      case "HIGH RISK":
        return "bg-orange-500/10 border-orange-500/30 text-orange-600 dark:text-orange-400";
      case "SUSPICIOUS":
        return "bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400";
      case "UNKNOWN":
        return "bg-yellow-500/10 border-yellow-500/30 text-yellow-600 dark:text-yellow-400";
      case "LOW RISK":
      case "SAFE":
        return "bg-blue-500/10 border-blue-500/30 text-blue-600 dark:text-blue-400";
      case "LIKELY LEGITIMATE":
        return "bg-teal-500/10 border-teal-500/30 text-teal-600 dark:text-teal-400";
      case "VERIFIED LEGITIMATE":
        return "bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400";
      default:
        return "bg-gray-500/10 border-gray-500/30 text-gray-600 dark:text-gray-400";
    }
  };

  const getIcon = () => {
    switch (verdict) {
      case "PHISHING": return "🚨";
      case "HIGH RISK": return "⚠️";
      case "SUSPICIOUS": return "⚠️";
      case "UNKNOWN": return "❓";
      case "LOW RISK": return "🛡️";
      case "SAFE": return "✓";
      case "LIKELY LEGITIMATE": return "✓";
      case "VERIFIED LEGITIMATE": return "🛡️";
      default: return "ℹ️";
    }
  };

  const style = getStyles();
  const icon = getIcon();

  return (
    <section className="rounded-[16px] border border-[var(--tm-border)] bg-[var(--tm-surface)] p-4 md:p-6 shadow-sm">
      <SectionHeader icon="⚖️" title="Final Security Decision" subtitle="Overall assessment based on accumulated intelligence" />
      
      <div className={`mt-5 flex flex-col md:flex-row items-center justify-between gap-6 rounded-[14px] border p-6 md:p-8 ${style}`}>
        <div className="flex flex-col items-center md:items-start text-center md:text-left">
          <span className="text-[11px] font-bold uppercase tracking-widest opacity-80 mb-1">Final Verdict</span>
          <div className="flex items-center gap-3">
            <span className="text-3xl md:text-4xl">{icon}</span>
            <span className="text-3xl md:text-4xl font-black tracking-tight">{verdict}</span>
          </div>
        </div>
        
        <div className="flex gap-8 items-center shrink-0">
          <div className="flex flex-col items-center">
            <span className="text-[11px] font-bold uppercase tracking-widest opacity-80">Risk</span>
            <span className="text-2xl font-bold">{data.risk_score ?? 0}</span>
          </div>
          <div className="h-10 w-px bg-current opacity-20"></div>
          <div className="flex flex-col items-center">
            <span className="text-[11px] font-bold uppercase tracking-widest opacity-80">Confidence</span>
            <span className="text-2xl font-bold">{data.confidence ?? 0}%</span>
          </div>
        </div>
      </div>

      <div className="mt-5 rounded-[12px] border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] p-5">
        <h3 className="text-[12px] font-bold uppercase tracking-wider text-[var(--tm-text-secondary)] mb-2">Security Recommendation</h3>
        <p className="text-[14px] leading-relaxed text-[var(--tm-text)] font-medium">
          {data.recommendation || "No immediate threats detected."}
        </p>
      </div>
    </section>
  );
}

export default FinalDecision;
