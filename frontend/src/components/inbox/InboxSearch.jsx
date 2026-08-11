import React, { useState } from "react";

function InboxSearch({
  searchQuery,
  setSearchQuery,
  filterStatus,
  setFilterStatus,
  sortOption,
  setSortOption,
  onRefresh,
}) {
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await onRefresh();
    setTimeout(() => setIsRefreshing(false), 500); // minimum rotation animation duration
  };

  return (
    <div className="flex flex-col gap-3 p-4 border-b border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">
      {/* Search Input */}
      <div className="relative flex items-center">
        <span className="absolute left-3 text-[var(--tm-text-muted)] pointer-events-none">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </span>
        <input
          type="text"
          placeholder="Search sender, subject..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] py-2 pl-9 pr-4 text-sm text-[var(--tm-text)] placeholder-[var(--tm-text-muted)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow"
        />
        <button 
          onClick={handleRefresh}
          className="ml-2 flex flex-shrink-0 items-center justify-center w-10 h-10 rounded-[10px] bg-[var(--tm-surface)] border border-[var(--tm-border)] hover:bg-[var(--tm-accent)]/5 hover:border-[var(--tm-accent)]/30 text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] transition-all cursor-pointer"
          title="Refresh Inbox"
        >
          <svg className={`w-4 h-4 ${isRefreshing ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* Filters and Sort */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="w-full appearance-none rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface)] px-3 py-1.5 pr-8 text-[12px] font-medium text-[var(--tm-text-secondary)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow cursor-pointer"
          >
            <option value="ALL">All Status</option>
            <option value="VERIFIED LEGITIMATE">Verified Legitimate</option>
            <option value="LIKELY LEGITIMATE">Likely Legitimate</option>
            <option value="UNKNOWN">Unknown</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="HIGH RISK">High Risk</option>
            <option value="PHISHING">Phishing</option>
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-[var(--tm-text-muted)]">
            <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" /></svg>
          </div>
        </div>

        <div className="relative flex-1">
          <select
            value={sortOption}
            onChange={(e) => setSortOption(e.target.value)}
            className="w-full appearance-none rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface)] px-3 py-1.5 pr-8 text-[12px] font-medium text-[var(--tm-text-secondary)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow cursor-pointer"
          >
            <option value="NEWEST">Newest First</option>
            <option value="OLDEST">Oldest First</option>
            <option value="RISK_HIGH">Highest Risk</option>
            <option value="RISK_LOW">Lowest Risk</option>
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-[var(--tm-text-muted)]">
            <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" /></svg>
          </div>
        </div>
      </div>
    </div>
  );
}

export default InboxSearch;
