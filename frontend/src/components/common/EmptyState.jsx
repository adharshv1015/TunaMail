import React from "react";

function EmptyState({ icon, message }) {
  return (
    <div className="mt-5 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] py-8 text-center">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-[var(--tm-surface)] text-xl border border-[var(--tm-border)]">
        {icon}
      </div>
      <p className="mt-3 text-sm font-medium text-[var(--tm-text-secondary)]">{message}</p>
    </div>
  );
}

export default EmptyState;
