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
          ? "bg-[#eef2ff] dark:bg-[#111c35] border-l-[3px] border-l-[#6366f1] shadow-sm" 
          : "bg-transparent border-l-[3px] border-l-transparent hover:bg-[#f8fafc] dark:hover:bg-[#0f172a]"
      }`}
    >
      <div className="flex items-start justify-between w-full">
        <span className={`font-semibold truncate pr-2 ${senderColor}`}>
          {senderName}
        </span>
        <span className="text-[11px] text-[var(--tm-text-muted)] shrink-0 pt-0.5">
          {dateStr}
        </span>
      </div>

      <div className={`text-[13px] truncate ${subjectColor}`}>
        {subject}
      </div>

      <div className="flex items-center justify-between mt-1">
        <span className="text-[12px] font-medium text-[var(--tm-text-muted)]">
          Risk: <span className={riskScore > 50 ? "text-orange-500 dark:text-orange-400 font-bold" : "text-[var(--tm-text-secondary)]"}>{riskScore}</span>
        </span>
        <VerdictBadge verdict={verdict} />
      </div>
    </button>
  );
}

export default EmailListItem;

