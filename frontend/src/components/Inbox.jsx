import React, { useEffect, useState, useMemo } from "react";
import { getMessages } from "../api/api";
import InboxHeader from "./inbox/InboxHeader";
import InboxSearch from "./inbox/InboxSearch";
import EmailList from "./inbox/EmailList";

function Inbox({ selectedMessageId, onSelectMessage, onAuthError, isConnected }) {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Search, Filter, Sort state
  const [searchQuery, setSearchQuery] = useState("");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [sortOption, setSortOption] = useState("NEWEST");

  useEffect(() => {
    if (isConnected === false) {
      setMessages([]);
      setLoading(false);
      return;
    }
    
    const controller = new AbortController();
    loadMessages(controller.signal);
    return () => {
        controller.abort();
    };
  }, [isConnected]);

  async function loadMessages(signal) {
    try {
      setLoading(true);
      const data = await getMessages({ signal });
      const loadedMessages = data.messages || [];
      setMessages(loadedMessages);

    } catch (error) {
      if (error.name === 'AbortError') {
          return;
      }
      if (error.message && (error.message.includes("UNAUTHORIZED") || error.message.includes("Failed to fetch") || error.message.includes("401"))) {
        onAuthError?.();
      }
      console.error("Failed to load messages:", error);
    } finally {
      if (!signal || !signal.aborted) {
          setLoading(false);
      }
    }
  }

  // Filter and Sort logic
  const filteredAndSortedMessages = useMemo(() => {
    let result = [...messages];

    // Search
    if (searchQuery.trim() !== "") {
      const q = searchQuery.toLowerCase();
      result = result.filter(msg => 
        (msg.from && msg.from.toLowerCase().includes(q)) || 
        (msg.subject && msg.subject.toLowerCase().includes(q))
      );
    }

    // Filter by Verdict Status
    if (filterStatus !== "ALL") {
      result = result.filter(msg => {
        const verdict = msg.analysis?.decision?.verdict?.toUpperCase() || "SAFE";
        return verdict === filterStatus;
      });
    }

    // Sort
    result.sort((a, b) => {
      const dateA = new Date(a.date).getTime() || 0;
      const dateB = new Date(b.date).getTime() || 0;
      const riskA = a.analysis?.decision?.risk_score ?? 0;
      const riskB = b.analysis?.decision?.risk_score ?? 0;

      switch (sortOption) {
        case "NEWEST":
          return dateB - dateA;
        case "OLDEST":
          return dateA - dateB;
        case "RISK_HIGH":
          return riskB - riskA;
        case "RISK_LOW":
          return riskA - riskB;
        default:
          return 0;
      }
    });

    return result;
  }, [messages, searchQuery, filterStatus, sortOption]);

  return (
    <div className="flex flex-col h-full bg-[var(--tm-surface-secondary)]">
      <InboxHeader messageCount={messages.length} />
      
      <InboxSearch
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        filterStatus={filterStatus}
        setFilterStatus={setFilterStatus}
        sortOption={sortOption}
        setSortOption={setSortOption}
        onRefresh={loadMessages}
      />
      
      <EmailList 
        messages={filteredAndSortedMessages}
        loading={loading}
        selectedMessageId={selectedMessageId}
        onSelectMessage={onSelectMessage}
        isConnected={isConnected}
      />
    </div>
  );
}

export default Inbox;
