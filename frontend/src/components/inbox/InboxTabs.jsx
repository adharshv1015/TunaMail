import React from "react";

function InboxTabs({ activeCategory, setActiveCategory }) {
  const tabs = [
    { id: "primary", label: "Primary", icon: "M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" },
    { id: "promotions", label: "Promotions", icon: "M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" },
    { id: "social", label: "Social", icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" },
    { id: "updates", label: "Updates", icon: "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" },
  ];

  return (
    <div className="flex border-b border-[var(--tm-border)] bg-[var(--tm-surface)]">
      {tabs.map((tab) => {
        const isActive = activeCategory === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => setActiveCategory(tab.id)}
            className={`flex flex-1 items-center justify-center gap-2 py-3 text-sm font-medium transition-colors border-b-2 ${
              isActive
                ? "border-[var(--tm-accent)] text-[var(--tm-accent)] bg-black/5"
                : "border-transparent text-[var(--tm-text-muted)] hover:bg-black/5 hover:text-[var(--tm-text-secondary)]"
            }`}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d={tab.icon} />
            </svg>
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

export default InboxTabs;
