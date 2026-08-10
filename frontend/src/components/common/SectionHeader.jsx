import React from "react";

function SectionHeader({ icon, title, subtitle }) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/10 text-lg">
        {icon}
      </div>
      <div>
        <h2 className="text-lg font-semibold text-[var(--tm-text)]">{title}</h2>
        <p className="mt-1 text-xs text-[var(--tm-text-secondary)]">{subtitle}</p>
      </div>
    </div>
  );
}

export default SectionHeader;
