import React, { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { getMessages } from "../api/api";
import InboxHeader from "./inbox/InboxHeader";
import InboxSearch from "./inbox/InboxSearch";
import InboxTabs from "./inbox/InboxTabs";
import EmailList from "./inbox/EmailList";

function Inbox({ selectedMessageId, onSelectMessage, onAuthError, isConnected, onRegisterAnalyzedCallback }) {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(false);

  // Local-only controls (do NOT trigger backend fetch)
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [sortOption, setSortOption] = useState("NEWEST");

  // Backend fetch controls (trigger backend refresh when changed)
  const [fetchLimit, setFetchLimit] = useState(10);
  const [fetchPeriod, setFetchPeriod] = useState("recent");

  // Server-side search fields
  const [serverSearch, setServerSearch] = useState({
    sender: "", subject: "", keyword: "", domain: "", after: "", before: "",
  });
  const [isServerSearch, setIsServerSearch] = useState(false);
  const [activeCategory, setActiveCategory] = useState("primary");

  // Pagination token history:
  // [{ page: 1, tokenUsed: null, nextToken: "A" }, ...]
  const [pageTokenHistory, setPageTokenHistory] = useState([]);
  const [currentPageIndex, setCurrentPageIndex] = useState(0);

  // Ref to track the active request so stale responses don't overwrite new state
  const requestIdRef = useRef(0);
  // Ref for AbortController
  const abortControllerRef = useRef(null);

  // ----------------------------------------------------------------
  // Core fetch function — receives search fields directly to avoid
  // stale closure bugs with setState + immediate fetchPage call.
  // ----------------------------------------------------------------
  const fetchPage = useCallback(async (pageToken = null, options = {}) => {
    const {
      isNewSearch = false,
      // Explicit search fields override state so we never read stale state
      searchFields = null,
      useServerSearch = false,
      limit = fetchLimit,
      period = fetchPeriod,
      category = activeCategory,
    } = options;

    // Cancel any in-flight request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;
    const reqId = ++requestIdRef.current;

    setLoading(true);

    try {
      const params = {
        signal: controller.signal,
        limit,
        period,
        pageToken: pageToken || undefined,
      };

      // Attach server search fields if this is a server search call
      const fields = searchFields || serverSearch;
      if (useServerSearch) {
        if (fields.sender)  params.sender  = fields.sender;
        if (fields.subject) params.subject = fields.subject;
        if (fields.domain)  params.domain  = fields.domain;
        if (fields.after)   params.after   = fields.after;
        if (fields.before)  params.before  = fields.before;
      }
      
      let finalKeyword = "";
      if (useServerSearch && fields.keyword) {
        finalKeyword = fields.keyword;
      }
      if (category) {
        finalKeyword = finalKeyword ? `${finalKeyword} category:${category}` : `category:${category}`;
      }
      if (finalKeyword) {
        params.keyword = finalKeyword;
      }

      const data = await getMessages(params);

      // Discard stale responses
      if (reqId !== requestIdRef.current) return;

      const loadedMessages = data.messages || [];
      const nextToken = data.pagination?.next_page_token || null;

      setMessages(loadedMessages);
      setHasMore(!!nextToken);

      // Track this page in history
      setPageTokenHistory(prev => {
        if (isNewSearch) {
          return [{ page: 1, tokenUsed: pageToken, nextToken }];
        }
        const nextPage = prev.length + 1;
        return [...prev, { page: nextPage, tokenUsed: pageToken, nextToken }];
      });
      setCurrentPageIndex(isNewSearch ? 0 : pageTokenHistory.length);

    } catch (error) {
      if (error.name === "AbortError") return;
      if (error.message && (error.message.includes("UNAUTHORIZED") || error.message.includes("401"))) {
        onAuthError?.();
      }
      console.error("Failed to load messages:", error);
    } finally {
      if (reqId === requestIdRef.current) {
        setLoading(false);
      }
    }
  // Only stable refs / primitive fetch controls as deps — search fields passed explicitly
  }, [fetchLimit, fetchPeriod, activeCategory, onAuthError, pageTokenHistory.length]);

  // Initial load and re-fetch when fetch controls change
  useEffect(() => {
    if (isConnected === false) {
      setMessages([]);
      setLoading(false);
      return;
    }
    setPageTokenHistory([]);
    setCurrentPageIndex(0);
    fetchPage(null, { isNewSearch: true, useServerSearch: isServerSearch });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isConnected, fetchLimit, fetchPeriod, activeCategory]);

  // ----------------------------------------------------------------
  // Server Search — passes search fields DIRECTLY to avoid stale state
  // ----------------------------------------------------------------
  const runServerSearch = useCallback((fields) => {
    // Clear the selected message and detail state before loading new results
    onSelectMessage(null);
    setPageTokenHistory([]);
    setCurrentPageIndex(0);
    setIsServerSearch(true);
    // Pass fields explicitly so we don't depend on isServerSearch state being updated
    fetchPage(null, {
      isNewSearch: true,
      useServerSearch: true,
      searchFields: fields,
    });
  }, [fetchPage, onSelectMessage]);

  const clearServerSearch = useCallback(() => {
    onSelectMessage(null);
    setIsServerSearch(false);
    setServerSearch({ sender: "", subject: "", keyword: "", domain: "", after: "", before: "" });
    setPageTokenHistory([]);
    setCurrentPageIndex(0);
    fetchPage(null, { isNewSearch: true, useServerSearch: false });
  }, [fetchPage, onSelectMessage]);

  // ----------------------------------------------------------------
  // Pagination — Load Older
  // ----------------------------------------------------------------
  const loadOlder = useCallback(() => {
    const currentEntry = pageTokenHistory[currentPageIndex];
    const nextToken = currentEntry?.nextToken;
    if (!nextToken) return;
    fetchPage(nextToken, { isNewSearch: false, useServerSearch: isServerSearch });
  }, [pageTokenHistory, currentPageIndex, fetchPage, isServerSearch]);

  const handleRefresh = useCallback(() => {
    onSelectMessage(null);
    setPageTokenHistory([]);
    setCurrentPageIndex(0);
    setIsServerSearch(false);
    setServerSearch({ sender: "", subject: "", keyword: "", domain: "", after: "", before: "" });
    fetchPage(null, { isNewSearch: true, useServerSearch: false });
  }, [fetchPage, onSelectMessage]);

  // ----------------------------------------------------------------
  // Local filter + sort (does NOT trigger backend fetch)
  // ----------------------------------------------------------------
  const filteredAndSortedMessages = useMemo(() => {
    let result = [...messages];

    if (searchQuery.trim() !== "") {
      const q = searchQuery.toLowerCase();
      result = result.filter(msg =>
        (msg.from && msg.from.toLowerCase().includes(q)) ||
        (msg.subject && msg.subject.toLowerCase().includes(q))
      );
    }

    if (filterStatus !== "ALL") {
      result = result.filter(msg => {
        const verdict = (msg.analysis?.decision?.verdict || msg.decision?.verdict || "UNANALYZED").toUpperCase();
        return verdict === filterStatus.toUpperCase();
      });
    }

    result.sort((a, b) => {
      const dateA = new Date(a.date).getTime() || 0;
      const dateB = new Date(b.date).getTime() || 0;
      const riskA = a.analysis?.decision?.risk_score ?? a.decision?.risk_score ?? 0;
      const riskB = b.analysis?.decision?.risk_score ?? b.decision?.risk_score ?? 0;

      switch (sortOption) {
        case "NEWEST":    return dateB - dateA;
        case "OLDEST":    return dateA - dateB;
        case "RISK_HIGH": return riskB - riskA;
        case "RISK_LOW":  return riskA - riskB;
        default: return 0;
      }
    });

    return result;
  }, [messages, searchQuery, filterStatus, sortOption]);

  // When EmailDetail finishes analysis, update that message's badge in the list.
  // Register this function with App so it can be called by EmailDetail's callback.
  const handleMessageAnalyzed = useCallback((messageId, analysisResult) => {
    setMessages(prev => prev.map(msg =>
      msg.id === messageId
        ? {
            ...msg,
            analysis_status: "ANALYZED",
            analysis: analysisResult.analysis,
            decision: analysisResult.decision,
          }
        : msg
    ));
  }, []);

  // Register the handler with App once it's stable
  useEffect(() => {
    onRegisterAnalyzedCallback?.(handleMessageAnalyzed);
  }, [handleMessageAnalyzed, onRegisterAnalyzedCallback]);

  const currentToken = pageTokenHistory[currentPageIndex]?.nextToken;

  return (
    <div className="flex flex-col h-full bg-[var(--tm-surface-secondary)]">
      <InboxHeader messageCount={messages.length} isServerSearch={isServerSearch} />

      <InboxSearch
        // Local controls
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        filterStatus={filterStatus}
        setFilterStatus={setFilterStatus}
        sortOption={sortOption}
        setSortOption={setSortOption}
        // Fetch controls
        fetchLimit={fetchLimit}
        setFetchLimit={setFetchLimit}
        fetchPeriod={fetchPeriod}
        setFetchPeriod={setFetchPeriod}
        // Server search
        serverSearch={serverSearch}
        setServerSearch={setServerSearch}
        isServerSearch={isServerSearch}
        onRunServerSearch={runServerSearch}
        onClearServerSearch={clearServerSearch}
        onRefresh={handleRefresh}
      />
      
      <InboxTabs 
        activeCategory={activeCategory} 
        setActiveCategory={setActiveCategory} 
      />

      <EmailList
        messages={filteredAndSortedMessages}
        loading={loading}
        selectedMessageId={selectedMessageId}
        onSelectMessage={onSelectMessage}
        isConnected={isConnected}
      />

      {/* Pagination footer */}
      <div className="shrink-0 px-4 py-3 border-t border-[var(--tm-border)] bg-[var(--tm-surface-secondary)] flex items-center justify-between gap-2">
        <span className="text-xs text-[var(--tm-text-muted)]">
          {pageTokenHistory.length > 0
            ? `Page ${currentPageIndex + 1} · ${messages.length} messages`
            : `${messages.length} messages`
          }
        </span>
        <button
          onClick={loadOlder}
          disabled={!hasMore || loading}
          className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-[var(--tm-border)] bg-[var(--tm-surface)] text-[var(--tm-text-secondary)] hover:text-[var(--tm-accent)] hover:border-[var(--tm-accent)]/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {hasMore ? "Load Older →" : "No older messages"}
        </button>
      </div>
    </div>
  );
}

export default Inbox;
