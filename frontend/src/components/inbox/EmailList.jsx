import React from "react";
import EmailListItem from "./EmailListItem";

function EmailList({ messages, loading, selectedMessageId, onSelectMessage, isConnected }) {
  if (loading) {
    return (
      <div className="flex-1 p-6 flex items-center justify-center">
        <div className="text-[var(--tm-text-secondary)] text-sm flex flex-col items-center gap-2">
          <span className="text-2xl animate-[spin_0.5s_linear_infinite]">◌</span>
          Loading messages...
        </div>
      </div>
    );
  }

  if (messages.length === 0) {
    if (isConnected === false) {
      return (
        <div className="flex-1 p-8 flex flex-col items-center justify-center text-center">
          <span className="text-3xl mb-2 text-[var(--tm-text-secondary)]">🔒</span>
          <div className="text-[var(--tm-text-secondary)] font-medium">Please connect to Gmail</div>
          <div className="text-xs text-[var(--tm-text-secondary)] mt-1">Connect your account to view emails.</div>
        </div>
      );
    }

    return (
      <div className="flex-1 p-8 flex flex-col items-center justify-center text-center">
        <span className="text-3xl mb-2 text-[var(--tm-text-secondary)]">📭</span>
        <div className="text-[var(--tm-text-secondary)] font-medium">No messages found.</div>
        <div className="text-xs text-[var(--tm-text-secondary)] mt-1">Try adjusting your filters or search.</div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto custom-scrollbar">
      {messages.map((msg) => (
        <EmailListItem
          key={msg.id}
          message={msg}
          isActive={selectedMessageId === msg.id}
          onClick={() => onSelectMessage(msg.id, messages)}
        />
      ))}
    </div>
  );
}

export default EmailList;
