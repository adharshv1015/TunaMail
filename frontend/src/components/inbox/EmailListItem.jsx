import React from "react";
import VerdictBadge from "../common/VerdictBadge";

function EmailListItem({ message, isActive, onClick }) {
  const decision = message.analysis?.decision || {};
  const riskScore = decision.risk_score ?? 0;
  const verdict = decision.verdict || "SAFE";
  
  const sender = message.from || "Unknown sender";
  const senderName = sender.split("<")[0].trim();
  const subject = message.subject?.trim() || "(No subject)";
  
  const dateStr = message.date ? new Date(message.date).toLocaleDateString(undefined, {
    month: "short", day: "numeric"
  }) : "";

  // Dynamic text colors based on state
  const senderColor = isActive 
    ? "text-slate-900 dark:text-slate-50" 
    : "text-[var(--tm-text)]";
    
  const subjectColor = isActive 
    ? "text-slate-700 dark:text-slate-300" 
    : "text-[var(--tm-text-secondary)]";

  return (
    <button
      onClick={onClick}
      className={`w-full text-left flex flex-col gap-1.5 border-b border-[var(--tm-border)] p-4 transition-colors duration-150 ease-in-out cursor-pointer ${
        isActive 
          ? "bg-indigo-50 dark:bg-[#14213d] border-l-[3px] border-l-indigo-400 dark:border-l-indigo-500 shadow-sm" 
          : "bg-white dark:bg-[#0d1528] border-l-[3px] border-l-transparent hover:bg-slate-50 dark:hover:bg-[#111c31]"
      }`}
    >
      <div className="flex items-start justify-between w-full">
        <span className={`font-semibold truncate pr-2 ${
          isActive ? "text-slate-900 dark:text-white" : "text-[var(--tm-text)]"
        }`}>
          {senderName}
        </span>
        <span className={`text-[11px] shrink-0 pt-0.5 ${
          isActive ? "text-slate-500 dark:text-slate-500" : "text-[var(--tm-text-muted)]"
        }`}>
          {dateStr}
        </span>
      </div>

      <div className={`text-[13px] truncate ${
        isActive ? "text-slate-600 dark:text-slate-400" : "text-[var(--tm-text-secondary)]"
      }`}>
        {subject}
      </div>

      <div className="flex items-center justify-between mt-1">
        <span className={`text-[12px] font-medium ${
          isActive ? "text-slate-600 dark:text-slate-400" : "text-[var(--tm-text-muted)]"
        }`}>
          Risk: <span className={riskScore > 50 ? "text-orange-600 dark:text-orange-400 font-bold" : (isActive ? "text-slate-600 dark:text-slate-400" : "text-[var(--tm-text-secondary)]")}>{riskScore}</span>
        </span>
        <VerdictBadge verdict={verdict} />
      </div>
    </button>
  );
}

export default EmailListItem;

