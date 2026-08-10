import React from "react";

function InboxHeader({ messageCount }) {
  return (
    <div className="p-4 border-b border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
      <div className="flex items-center justify-between">
        <h1 className="text-[24px] font-[700] text-[var(--tm-text)] tracking-tight">
          Inbox
        </h1>
        <span className="flex items-center justify-center rounded-full bg-[var(--tm-accent)]/10 px-2 py-0.5 text-xs font-semibold text-[var(--tm-accent)] border border-[var(--tm-accent)]/20">
          {messageCount} {messageCount === 1 ? "message" : "messages"}
        </span>
      </div>
      <div className="mt-1 text-[12px] text-[var(--tm-text-muted)] font-medium">
        Security intelligence monitoring
      </div>
    </div>
  );
}

export default InboxHeader;
