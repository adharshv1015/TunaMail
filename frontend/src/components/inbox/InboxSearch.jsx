import React, { useState } from "react";

function InboxSearch({
  // Local controls
  searchQuery, setSearchQuery,
  filterStatus, setFilterStatus,
  sortOption, setSortOption,
  // Fetch controls (trigger backend reload)
  fetchLimit, setFetchLimit,
  fetchPeriod, setFetchPeriod,
  // Server search
  serverSearch, setServerSearch,
  isServerSearch,
  onRunServerSearch,
  onClearServerSearch,
  onRefresh,
}) {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showFilters, setShowFilters] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await onRefresh();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const handleServerSearchChange = (field, value) => {
    setServerSearch(prev => ({ ...prev, [field]: value }));
  };

  const handleRunSearch = (e) => {
    e.preventDefault();
    // Pass a snapshot of the current field values directly so the fetch
    // doesn't rely on async React state updates settling first.
    onRunServerSearch({ ...serverSearch });
    setShowAdvanced(false);
  };

  const SelectWrapper = ({ children }) => (
    <div className="relative flex-1">
      {children}
      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-[var(--tm-text-muted)]">
        <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );

  const selectClass = "w-full appearance-none rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface)] px-3 py-1.5 pr-8 text-[12px] font-medium text-[var(--tm-text-secondary)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow cursor-pointer";
  const inputClass = "w-full rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface)] px-3 py-1.5 text-[12px] text-[var(--tm-text)] placeholder-[var(--tm-text-muted)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow";

  return (
    <div className="flex flex-col gap-0 border-b border-[var(--tm-border)] bg-[var(--tm-surface-secondary)]">

      {/* ── Quick Search Row ── */}
      <div className="flex items-center gap-2 p-3 pb-2">
        <div className="relative flex-1">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--tm-text-muted)] pointer-events-none">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </span>
          <input
            type="text"
            placeholder="Quick search loaded messages…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] py-2 pl-8 pr-4 text-[12px] text-[var(--tm-text)] placeholder-[var(--tm-text-muted)] outline-none focus:border-[var(--tm-accent)] focus:ring-[3px] focus:ring-[var(--tm-accent)]/10 transition-shadow"
          />
        </div>
        <button
          onClick={handleRefresh}
          className="flex shrink-0 items-center justify-center w-8 h-8 rounded-[10px] bg-[var(--tm-surface)] border border-[var(--tm-border)] hover:bg-[var(--tm-accent)]/5 hover:border-[var(--tm-accent)]/30 text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] transition-all cursor-pointer"
          title="Refresh Inbox"
        >
          <svg className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* ── Advanced Server Search Toggle ── */}
      <div className="px-3 pb-2">
        {isServerSearch ? (
          <div className="flex items-center gap-2 px-2 py-1 rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-[11px] text-indigo-500 dark:text-indigo-400">
            <span className="font-semibold">📡 Gmail Search active</span>
            <button onClick={onClearServerSearch} className="ml-auto text-[10px] underline hover:no-underline">
              Clear
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between px-1">
            <button
              onClick={() => setShowAdvanced(v => !v)}
              className="flex items-center gap-1.5 text-[11px] font-semibold text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] transition-colors"
            >
              <span>📡 Advanced Gmail Search</span>
              <span className="text-[var(--tm-text-muted)]">{showAdvanced ? "▲" : "▼"}</span>
            </button>
            
            <button
              onClick={() => setShowFilters(v => !v)}
              className="flex items-center gap-1.5 text-[11px] font-semibold text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] transition-colors"
            >
              <span>⚙️ Filters & Sort</span>
              <span className="text-[var(--tm-text-muted)]">{showFilters ? "▲" : "▼"}</span>
            </button>
          </div>
        )}
      </div>

      {/* ── Advanced Search Panel ── */}
      {showAdvanced && !isServerSearch && (
        <form onSubmit={handleRunSearch} className="mx-3 mb-3 p-3 rounded-xl border border-[var(--tm-border)] bg-[var(--tm-surface)] flex flex-col gap-2 shadow-sm">
          <p className="text-[10px] text-[var(--tm-text-muted)] font-medium uppercase tracking-wider mb-1">
            Searches your entire Gmail mailbox (server-side)
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input className={inputClass} placeholder="From (sender)" value={serverSearch.sender} onChange={e => handleServerSearchChange("sender", e.target.value)} />
            <input className={inputClass} placeholder="Subject" value={serverSearch.subject} onChange={e => handleServerSearchChange("subject", e.target.value)} />
            <input className={inputClass} placeholder="Keyword / domain" value={serverSearch.keyword} onChange={e => handleServerSearchChange("keyword", e.target.value)} />
            <input className={inputClass} placeholder="URL / domain" value={serverSearch.domain} onChange={e => handleServerSearchChange("domain", e.target.value)} />
            <input type="date" className={inputClass} title="After date" value={serverSearch.after} onChange={e => handleServerSearchChange("after", e.target.value)} />
            <input type="date" className={inputClass} title="Before date" value={serverSearch.before} onChange={e => handleServerSearchChange("before", e.target.value)} />
          </div>
          <div className="flex gap-2 mt-1">
            <button type="submit" className="flex-1 px-3 py-1.5 text-[12px] font-semibold rounded-lg bg-[var(--tm-accent)] text-white hover:bg-[var(--tm-accent-hover)] transition-colors border border-transparent">
              Search Gmail
            </button>
            <button type="button" onClick={() => setShowAdvanced(false)} className="px-3 py-1.5 text-[12px] font-medium rounded-lg border border-[var(--tm-border)] text-[var(--tm-text-secondary)] hover:bg-[var(--tm-surface-secondary)] transition-colors">
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* ── Inbox Fetch & Local Filters (Collapsible) ── */}
      {showFilters && (
        <div className="px-3 pb-3 flex flex-col gap-3 animate-fade-in">
          <div>
            <p className="text-[10px] text-[var(--tm-text-muted)] font-semibold uppercase tracking-wider mb-1.5 px-1">
              Inbox Fetch
            </p>
            <div className="grid grid-cols-2 gap-2">
              <SelectWrapper>
                <select value={fetchPeriod} onChange={e => setFetchPeriod(e.target.value)} className={selectClass}>
                  <option value="recent">Any Time</option>
                  <option value="month">Last 30 Days</option>
                  <option value="year">Last Year</option>
                </select>
              </SelectWrapper>
              <SelectWrapper>
                <select value={fetchLimit} onChange={e => setFetchLimit(Number(e.target.value))} className={selectClass}>
                  <option value={10}>10 messages</option>
                  <option value={25}>25 messages</option>
                  <option value={50}>50 messages</option>
                  <option value={100}>100 messages</option>
                </select>
              </SelectWrapper>
            </div>
          </div>
          
          <div>
            <p className="text-[10px] text-[var(--tm-text-muted)] font-semibold uppercase tracking-wider mb-1.5 px-1">
              Local Filters
            </p>
            <div className="grid grid-cols-2 gap-2">
              <SelectWrapper>
                <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className={selectClass}>
                  <option value="ALL">All Status</option>
                  <option value="VERIFIED LEGITIMATE">Verified Legitimate</option>
                  <option value="LIKELY LEGITIMATE">Likely Legitimate</option>
                  <option value="UNKNOWN">Unknown</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="HIGH RISK">High Risk</option>
                  <option value="PHISHING">Phishing</option>
                  <option value="UNANALYZED">Unanalyzed</option>
                </select>
              </SelectWrapper>
              <SelectWrapper>
                <select value={sortOption} onChange={e => setSortOption(e.target.value)} className={selectClass}>
                  <option value="NEWEST">Newest First</option>
                  <option value="OLDEST">Oldest First</option>
                  <option value="RISK_HIGH">Highest Risk</option>
                  <option value="RISK_LOW">Lowest Risk</option>
                </select>
              </SelectWrapper>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default InboxSearch;
