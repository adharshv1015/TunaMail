import React from "react";

export function getVerdictStyle(verdict = "") {
  const v = verdict.toUpperCase();
  switch (v) {
    case "PHISHING":
      return "bg-red-50 text-red-700 border-red-200 dark:bg-red-500/12 dark:text-red-400 dark:border-red-500/25";
    case "HIGH RISK":
      return "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-500/12 dark:text-orange-400 dark:border-orange-500/25";
    case "SUSPICIOUS":
      return "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-500/12 dark:text-amber-400 dark:border-amber-500/25";
    case "UNKNOWN":
      return "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-500/12 dark:text-yellow-400 dark:border-yellow-500/25";
    case "LOW RISK":
    case "SAFE":
      return "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-500/12 dark:text-blue-400 dark:border-blue-500/25";
    case "LIKELY LEGITIMATE":
      return "bg-teal-50 text-teal-700 border-teal-200 dark:bg-teal-500/12 dark:text-teal-400 dark:border-teal-500/25";
    case "VERIFIED LEGITIMATE":
      return "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/12 dark:text-emerald-400 dark:border-emerald-500/25";
    default:
      return "bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-500/12 dark:text-[var(--tm-text-secondary)] dark:border-slate-500/25";
  }
}

export function VerdictBadge({ verdict, className = "" }) {
  const v = verdict || "UNKNOWN";
  return (
    <span
      className={`inline-flex items-center justify-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${getVerdictStyle(
        v
      )} ${className}`}
    >
      {v}
    </span>
  );
}

export default VerdictBadge;
