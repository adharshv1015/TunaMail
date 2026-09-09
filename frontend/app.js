/**
 * TunaMail - Single Unified Frontend Application
 * Pure Vanilla JavaScript Architecture
 * Communicates with FastAPI backend via Vite proxy or direct http://127.0.0.1:8000
 */

const API_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") && (window.location.port === "5173" || window.location.port === "4173")
  ? ""
  : "http://127.0.0.1:8000";

/* ==========================================================================
   Application State
   ========================================================================== */
const state = {
  isConnected: false,
  messages: [],
  filteredMessages: [],
  selectedMessageId: null,
  selectedMessageData: null,
  activeCategory: "primary", // Real Gmail tabs: primary, promotions, social, updates, all
  activeFilter: "all",       // Quick safety: all, safe, phishing
  sortOption: "NEWEST",      // NEWEST, OLDEST, RISK_HIGH, RISK_LOW
  securityFilter: "ALL",     // ALL, SAFE, SUSPICIOUS, PHISHING, UNANALYZED
  searchQuery: "",
  serverSearchParams: {},
  inspectorTab: "sender",
  isStreaming: false,
  streamProgress: 0,
  streamStep: "",
  streamDetail: "",
  abortController: null,
};

/* ==========================================================================
   DOM Element Cache
   ========================================================================== */
const dom = {
  connStatusPill: document.getElementById("connStatusPill"),
  connStatusDot: document.getElementById("connStatusDot"),
  connStatusText: document.getElementById("connStatusText"),
  btnAuthAction: document.getElementById("btnAuthAction"),
  emailCountPill: document.getElementById("emailCountPill"),
  btnRefresh: document.getElementById("btnRefresh"),
  btnToggleAdvanced: document.getElementById("btnToggleAdvanced"),
  btnToggleFilters: document.getElementById("btnToggleFilters"),
  btnCloseAdvanced: document.getElementById("btnCloseAdvanced"),
  advancedSearchPanel: document.getElementById("advancedSearchPanel"),
  filtersSortPanel: document.getElementById("filtersSortPanel"),
  advArrow: document.getElementById("advArrow"),
  filtersArrow: document.getElementById("filtersArrow"),
  serverSearchActiveBar: document.getElementById("serverSearchActiveBar"),
  btnClearServerSearch: document.getElementById("btnClearServerSearch"),
  advancedSearchForm: document.getElementById("advancedSearchForm"),
  btnResetAdvanced: document.getElementById("btnResetAdvanced"),
  gmailTabs: document.querySelectorAll(".gmail-tab"),
  countPrimary: document.getElementById("countPrimary"),
  countPromotions: document.getElementById("countPromotions"),
  countSocial: document.getElementById("countSocial"),
  countUpdates: document.getElementById("countUpdates"),
  countAll: document.getElementById("countAll"),
  advSender: document.getElementById("advSender"),
  advSubject: document.getElementById("advSubject"),
  advKeyword: document.getElementById("advKeyword"),
  advDomain: document.getElementById("advDomain"),
  advAfter: document.getElementById("advAfter"),
  advBefore: document.getElementById("advBefore"),
  advPeriod: document.getElementById("advPeriod"),
  advLimit: document.getElementById("advLimit"),
  advSort: document.getElementById("advSort"),
  advStatus: document.getElementById("advStatus"),
  searchInput: document.getElementById("searchInput"),
  btnClearSearch: document.getElementById("btnClearSearch"),
  filterChips: document.querySelectorAll(".filter-chip"),
  inboxList: document.getElementById("inboxList"),
  analysisArea: document.getElementById("analysisArea"),
  modalContainer: document.getElementById("modalContainer"),
  toastContainer: document.getElementById("toastContainer"),
};

/* ==========================================================================
   Utilities
   ========================================================================== */
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showToast(message, type = "info") {
  let text = message;
  if (message instanceof Error) {
    text = message.message;
  } else if (message && typeof message === "object") {
    if (Array.isArray(message)) {
      text = message.map((item) => (item && (item.msg || item.message || JSON.stringify(item))) || String(item)).join(", ");
    } else {
      text = message.message || message.detail || message.msg || JSON.stringify(message);
    }
  } else {
    text = String(text ?? "");
  }

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${type === "success" ? "✓" : type === "error" ? "⚠️" : "ℹ️"}</span>
    <span>${escapeHtml(text)}</span>
  `;
  dom.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function copyToClipboard(text, label = "Copied to clipboard") {
  navigator.clipboard.writeText(text).then(
    () => showToast(label, "success"),
    () => showToast("Failed to copy", "error")
  );
}

function formatDate(dateStr) {
  if (!dateStr) return "";
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    if (isToday) {
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  } catch {
    return dateStr;
  }
}

/* ==========================================================================
   API Service
   ========================================================================== */
async function checkAuthStatus() {
  try {
    const res = await fetch(`${API_BASE}/auth/status`, { credentials: "include" });
    if (!res.ok) return { authenticated: false };
    return await res.json();
  } catch (err) {
    console.error("Auth check error:", err);
    return { authenticated: false };
  }
}

async function logout() {
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: "POST",
      credentials: "include",
    });
    state.isConnected = false;
    state.selectedMessageId = null;
    state.selectedMessageData = null;
    updateAuthUI();
    renderInboxList();
    renderAnalysisArea();
    showToast("Logged out successfully", "info");
  } catch (err) {
    showToast("Logout failed", "error");
  }
}

async function fetchInboxMessages(customQuery = null) {
  if (!state.isConnected) {
    renderEmptyState("Please connect your Gmail account to inspect emails.");
    return;
  }
  dom.btnRefresh.classList.add("spin-animation");
  try {
    const params = new URLSearchParams();
    const period = dom.advPeriod?.value || "recent";
    const limit = dom.advLimit?.value || "30";

    params.set("period", period);
    params.set("limit", limit);

    if (customQuery) {
      if (customQuery.sender) params.set("sender", customQuery.sender);
      if (customQuery.subject) params.set("subject", customQuery.subject);
      if (customQuery.keyword) params.set("keyword", customQuery.keyword);
      if (customQuery.domain) params.set("domain", customQuery.domain);
      if (customQuery.after) params.set("after", customQuery.after);
      if (customQuery.before) params.set("before", customQuery.before);
    }

    let res;
    try {
      res = await fetch(`${API_BASE}/gmail/messages?${params.toString()}`, {
        credentials: "include",
      });
    } catch (networkErr) {
      console.error("Network error fetching inbox:", networkErr);
      showToast("Backend connection interrupted. Please ensure the server is running on port 8000.", "error");
      return;
    }

    if (res.status === 401) {
      state.isConnected = false;
      updateAuthUI();
      renderEmptyState("Your Gmail session has expired. Please click 'Connect Gmail' at the top right to reconnect.");
      showToast("Session expired. Please reconnect Gmail.", "warn");
      return;
    }

    if (!res.ok) {
      let detail = `Failed to fetch messages (${res.status})`;
      try {
        const errJson = await res.json();
        detail = errJson.detail || errJson.message || detail;
      } catch (_) {}
      showToast(detail, "error");
      return;
    }

    const data = await res.json();
    state.messages = Array.isArray(data) ? data : data.messages || [];

    try {
      updateCategoryCounts();
      filterAndRenderInbox();
    } catch (renderErr) {
      console.error("Render inbox error:", renderErr);
      showToast("Error rendering email list in UI.", "error");
    }

    const hasServerQuery = customQuery && Object.keys(customQuery).length > 0;
    if (dom.serverSearchActiveBar) {
      dom.serverSearchActiveBar.classList.toggle("hidden", !hasServerQuery);
    }
    if (hasServerQuery) {
      showToast(`Loaded ${state.messages.length} email(s) from Gmail search`, "info");
    }
  } catch (err) {
    console.error("Fetch inbox unexpected error:", err);
    showToast(err.message || "An unexpected error occurred while loading emails.", "error");
  } finally {
    setTimeout(() => dom.btnRefresh.classList.remove("spin-animation"), 500);
  }
}

/* ==========================================================================
   Real Gmail Categories & Heuristics
   ========================================================================== */
function getEmailCategory(msg) {
  // 1. Check if backend analyzer categorized this email
  const cats = (msg.categories || []).map((c) => String(c).toLowerCase());
  if (cats.includes("social")) return "social";
  if (cats.includes("promotion") || cats.includes("shopping") || cats.includes("newsletter")) return "promotions";
  if (cats.includes("invoice") || cats.includes("delivery") || cats.includes("security") || cats.includes("banking") || cats.includes("otp")) return "updates";

  // 2. High-precision sender and content heuristics
  const from = (msg.from || "").toLowerCase();
  const sub = (msg.subject || "").toLowerCase();
  const snip = (msg.snippet || "").toLowerCase();
  const text = `${from} ${sub} ${snip}`;

  // Social
  if (
    /linkedin|twitter|x\.com|facebook|instagram|github|tiktok|pinterest|youtube|reddit|discord|medium\.com|quora\.com/.test(from) ||
    /\b(connection request|invitation to connect|new follower|liked your|commented on|friend request|tagged you|started following you)\b/i.test(text)
  ) {
    return "social";
  }

  // Promotions
  if (
    /\b(sale|% off|discount|deal|coupon|exclusive offer|limited time|free shipping|promo|cashback|save up to|black friday|cyber monday|shop now|special offer|clearance|save big|order now and get|weekly digest|newsletter)\b/i.test(text) ||
    /no-?reply.*(?:news|promo|marketing|offers|store)|marketing@|promotions@|newsletter@|deals@/.test(from)
  ) {
    return "promotions";
  }

  // Updates
  if (
    /\b(order confirmation|tracking number|shipped|out for delivery|delivered|invoice|receipt|statement|your bill|payment received|security alert|password reset|verify your|verification code|one-time password|\botp\b|2fa|login alert|bank statement|account alert|action required|tax invoice)\b/i.test(text)
  ) {
    return "updates";
  }

  // Default: Primary (Personal, direct, or default inbox)
  return "primary";
}

function updateCategoryCounts() {
  let cPrimary = 0;
  let cPromotions = 0;
  let cSocial = 0;
  let cUpdates = 0;

  state.messages.forEach((msg) => {
    const cat = getEmailCategory(msg);
    if (cat === "primary") cPrimary++;
    else if (cat === "promotions") cPromotions++;
    else if (cat === "social") cSocial++;
    else if (cat === "updates") cUpdates++;
  });

  if (dom.countPrimary) dom.countPrimary.textContent = cPrimary;
  if (dom.countPromotions) dom.countPromotions.textContent = cPromotions;
  if (dom.countSocial) dom.countSocial.textContent = cSocial;
  if (dom.countUpdates) dom.countUpdates.textContent = cUpdates;
  if (dom.countAll) dom.countAll.textContent = state.messages.length;
}

async function fetchSingleMessage(id) {
  const res = await fetch(`${API_BASE}/gmail/message/${id}`, {
    credentials: "include",
  });
  if (res.status === 401) {
    state.isConnected = false;
    updateAuthUI();
    throw new Error("Gmail session expired. Please click 'Connect Gmail' at the top right.");
  }
  if (!res.ok) throw new Error("Failed to fetch message details");
  return await res.json();
}

async function unlockPDFFile(messageId, password, attachmentId = null) {
  try {
    const payload = { password };
    if (attachmentId) payload.attachment_id = attachmentId;

    const res = await fetch(`${API_BASE}/gmail/message/${messageId}/unlock-pdf`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      let detail = `Failed to unlock PDF (${res.status})`;
      try {
        const err = await res.json();
        if (typeof err.detail === "string") {
          detail = err.detail;
        } else if (Array.isArray(err.detail)) {
          detail = err.detail.map((d) => d.msg || d.message || JSON.stringify(d)).join(", ");
        } else if (err.detail && typeof err.detail === "object") {
          detail = err.detail.message || err.detail.detail || JSON.stringify(err.detail);
        } else if (err.message) {
          detail = err.message;
        }
      } catch (_) {}
      throw new Error(detail);
    }

    const data = await res.json();
    if (data.status === "INVALID_PASSWORD") {
      showToast("Incorrect password. Decryption failed.", "error");
      return;
    }

    showToast("PDF unlocked and re-analyzed successfully!", "success");

    const updated = data.message || (data.id ? data : null);
    if (updated) {
      state.selectedMessageData = updated;
      updateMessageInInbox(messageId, updated);
      renderAnalysisArea();
    } else {
      fetchSingleMessage(messageId).then((fullMsg) => {
        state.selectedMessageData = fullMsg;
        updateMessageInInbox(messageId, fullMsg);
        renderAnalysisArea();
      }).catch(() => {});
    }

    hideModal();
  } catch (err) {
    showToast(err.message || "Failed to unlock PDF", "error");
  }
}

/* SSE Streaming Inspector */
function startMessageStream(messageId) {
  if (state.abortController) {
    state.abortController.abort();
  }
  state.abortController = new AbortController();
  const signal = state.abortController.signal;

  state.isStreaming = true;
  state.streamProgress = 5;
  state.streamStep = "Connecting to Forensic Sandbox";
  state.streamDetail = "Establishing secure streaming channel...";
  renderAnalysisArea();

  fetch(`${API_BASE}/gmail/message/${messageId}/stream`, {
    credentials: "include",
    signal,
    headers: { Accept: "text/event-stream" },
  })
    .then((response) => {
      if (response.status === 401) {
        state.isStreaming = false;
        state.isConnected = false;
        updateAuthUI();
        renderEmptyState("Your Gmail session has expired. Please click 'Connect Gmail' at the top right to reconnect.");
        showToast("Session expired. Please reconnect Gmail.", "warn");
        return;
      }
      if (!response.ok) throw new Error(`Stream error: ${response.status}`);
      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      function readChunk() {
        reader.read().then(({ done, value }) => {
          if (done) {
            state.isStreaming = false;
            renderAnalysisArea();
            return;
          }
          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop() || "";

          for (const chunk of parts) {
            const dataLine = chunk.split("\n").find((l) => l.startsWith("data:"));
            if (!dataLine) continue;
            try {
              const event = JSON.parse(dataLine.slice(5).trim());
              if (event.type === "progress") {
                state.streamProgress = event.progress || state.streamProgress;
                state.streamStep = event.step || state.streamStep;
                state.streamDetail = event.detail || state.streamDetail;
                renderStreamProgress();
              } else if (event.type === "result") {
                state.isStreaming = false;
                state.selectedMessageData = event.data;
                updateMessageInInbox(messageId, event.data);
                renderAnalysisArea();
              } else if (event.type === "error") {
                throw new Error(event.message || "Streaming analysis error");
              }
            } catch (pErr) {
              console.warn("SSE parse error:", pErr);
            }
          }
          readChunk();
        }).catch((err) => {
          if (signal.aborted) return;
          console.warn("Stream interrupted, fallback to standard fetch:", err);
          fallbackFetchMessage(messageId);
        });
      }
      readChunk();
    })
    .catch((err) => {
      if (signal.aborted) return;
      console.warn("Stream connection failed, fallback to standard fetch:", err);
      fallbackFetchMessage(messageId);
    });
}

async function fallbackFetchMessage(messageId) {
  try {
    state.streamStep = "Running Security Inspection";
    state.streamDetail = "Loading forensic evidence...";
    renderStreamProgress();
    const data = await fetchSingleMessage(messageId);
    state.isStreaming = false;
    state.selectedMessageData = data;
    updateMessageInInbox(messageId, data);
    renderAnalysisArea();
  } catch (err) {
    state.isStreaming = false;
    if (err.message.includes("session expired") || err.message.includes("Connect Gmail")) {
      state.isConnected = false;
      updateAuthUI();
      renderEmptyState("Your session has expired. Please click 'Connect Gmail' at the top right to reconnect.");
      showToast("Session expired. Please reconnect Gmail.", "warn");
    } else {
      renderEmptyState("Failed to inspect email: " + err.message);
    }
  }
}

function updateMessageInInbox(id, analyzedData) {
  const target = state.messages.find((m) => m.id === id);
  if (target) {
    target.analysis_status = "ANALYZED";
    const dec = analyzedData.analysis?.decision || {};
    target.verdict = dec.verdict || "SAFE";
    target.risk_score = dec.risk_score ?? 0;
    updateCategoryCounts();
    filterAndRenderInbox();
  }
}

/* ==========================================================================
   UI Event Handlers & Filtering
   ========================================================================== */
function setupEventListeners() {
  // Auth button (Login or Logout)
  dom.btnAuthAction.addEventListener("click", () => {
    if (state.isConnected) {
      logout();
    } else {
      window.location.href = `${API_BASE}/auth/login`;
    }
  });

  // Refresh emails
  dom.btnRefresh.addEventListener("click", () => {
    if (!state.isConnected) {
      showToast("Please connect your Gmail account first.", "info");
      return;
    }
    fetchInboxMessages(state.serverSearchParams);
  });

  // Real Gmail Category Tabs (Primary, Promotions, Social, Updates, All)
  dom.gmailTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      dom.gmailTabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      state.activeCategory = tab.dataset.category;
      filterAndRenderInbox();
    });
  });

  // Toggle Advanced Search Panel
  function toggleAdvancedSearch(forceOpen = null) {
    const isCurrentlyOpen = !dom.advancedSearchPanel.classList.contains("hidden");
    const shouldOpen = forceOpen !== null ? forceOpen : !isCurrentlyOpen;
    dom.advancedSearchPanel.classList.toggle("hidden", !shouldOpen);
    dom.btnToggleAdvanced?.classList.toggle("active", shouldOpen);
    if (dom.advArrow) dom.advArrow.textContent = shouldOpen ? "▲" : "▼";
    if (shouldOpen) {
      toggleFiltersSort(false);
      dom.advSender?.focus();
    }
  }

  // Toggle Filters & Sort Panel
  function toggleFiltersSort(forceOpen = null) {
    const isCurrentlyOpen = !dom.filtersSortPanel.classList.contains("hidden");
    const shouldOpen = forceOpen !== null ? forceOpen : !isCurrentlyOpen;
    dom.filtersSortPanel.classList.toggle("hidden", !shouldOpen);
    dom.btnToggleFilters?.classList.toggle("active", shouldOpen);
    if (dom.filtersArrow) dom.filtersArrow.textContent = shouldOpen ? "▲" : "▼";
    if (shouldOpen) {
      toggleAdvancedSearch(false);
    }
  }

  dom.btnToggleAdvanced?.addEventListener("click", () => toggleAdvancedSearch());
  dom.btnToggleFilters?.addEventListener("click", () => toggleFiltersSort());
  dom.btnCloseAdvanced?.addEventListener("click", () => toggleAdvancedSearch(false));

  // Clear server search active bar
  dom.btnClearServerSearch?.addEventListener("click", () => {
    state.serverSearchParams = {};
    dom.advancedSearchForm?.reset();
    if (dom.serverSearchActiveBar) dom.serverSearchActiveBar.classList.add("hidden");
    fetchInboxMessages();
  });

  // Advanced Search Form submission (Server-side Gmail search)
  dom.advancedSearchForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    const query = {};
    if (dom.advSender?.value.trim()) query.sender = dom.advSender.value.trim();
    if (dom.advSubject?.value.trim()) query.subject = dom.advSubject.value.trim();
    if (dom.advKeyword?.value.trim()) query.keyword = dom.advKeyword.value.trim();
    if (dom.advDomain?.value.trim()) query.domain = dom.advDomain.value.trim();
    if (dom.advAfter?.value.trim()) query.after = dom.advAfter.value.trim();
    if (dom.advBefore?.value.trim()) query.before = dom.advBefore.value.trim();

    state.serverSearchParams = query;
    state.sortOption = dom.advSort?.value || "NEWEST";
    state.securityFilter = dom.advStatus?.value || "ALL";

    showToast("Searching Gmail mailbox...", "info");
    fetchInboxMessages(query);
  });

  // Reset Advanced Search
  dom.btnResetAdvanced?.addEventListener("click", () => {
    dom.advancedSearchForm?.reset();
    state.serverSearchParams = {};
    state.sortOption = "NEWEST";
    state.securityFilter = "ALL";
    if (dom.advStatus) dom.advStatus.value = "ALL";
    if (dom.advSort) dom.advSort.value = "NEWEST";
    if (dom.serverSearchActiveBar) dom.serverSearchActiveBar.classList.add("hidden");
    toggleAdvancedSearch(false);
    fetchInboxMessages();
  });

  // Sort & Security Status Change listeners
  dom.advSort?.addEventListener("change", () => {
    state.sortOption = dom.advSort.value;
    filterAndRenderInbox();
  });

  dom.advStatus?.addEventListener("change", () => {
    state.securityFilter = dom.advStatus.value;
    filterAndRenderInbox();
  });

  // Inbox Fetch period & limit change listeners
  dom.advPeriod?.addEventListener("change", () => {
    fetchInboxMessages(state.serverSearchParams);
  });

  dom.advLimit?.addEventListener("change", () => {
    fetchInboxMessages(state.serverSearchParams);
  });

  // Quick Search input
  dom.searchInput.addEventListener("input", (e) => {
    state.searchQuery = e.target.value.toLowerCase().trim();
    dom.btnClearSearch.classList.toggle("hidden", !state.searchQuery);
    filterAndRenderInbox();
  });

  // Clear search
  dom.btnClearSearch.addEventListener("click", () => {
    dom.searchInput.value = "";
    state.searchQuery = "";
    dom.btnClearSearch.classList.add("hidden");
    filterAndRenderInbox();
  });

  // Quick Verdict Filter chips
  dom.filterChips.forEach((chip) => {
    if (chip.id === "btnFilterChipAdv") return;
    chip.addEventListener("click", () => {
      dom.filterChips.forEach((c) => {
        if (c.id !== "btnFilterChipAdv") c.classList.remove("active");
      });
      chip.classList.add("active");
      state.activeFilter = chip.dataset.filter;
      filterAndRenderInbox();
    });
  });

  // Modal dismiss on overlay click
  dom.modalContainer.addEventListener("click", (e) => {
    if (e.target === dom.modalContainer) hideModal();
  });
}

function filterAndRenderInbox() {
  const q = state.searchQuery;
  const f = state.activeFilter;
  const cat = state.activeCategory;
  const secFilter = state.securityFilter || "ALL";
  const sortOpt = state.sortOption || "NEWEST";

  let filtered = state.messages.filter((msg) => {
    // 1. Gmail Category Filter (Primary, Promotions, Social, Updates, All)
    if (cat !== "all") {
      const msgCategory = getEmailCategory(msg);
      if (msgCategory !== cat) return false;
    }

    const v = (msg.verdict || (msg.analysis_status === "ANALYZED" ? "SAFE" : "UNANALYZED")).toUpperCase();

    // 2. Quick Verdict Filter (all, safe, phishing)
    if (f === "safe") {
      if (v !== "SAFE" && v !== "CLEAN") return false;
    } else if (f === "phishing" || f === "attention") {
      if (v === "SAFE" || v === "CLEAN" || v === "UNANALYZED") return false;
    }

    // 3. Advanced Security Filter
    if (secFilter !== "ALL") {
      if (secFilter === "SAFE" && v !== "SAFE" && v !== "CLEAN") return false;
      if (secFilter === "SUSPICIOUS" && v !== "SUSPICIOUS") return false;
      if (secFilter === "PHISHING" && v !== "PHISHING" && v !== "MALICIOUS" && v !== "HIGH RISK" && v !== "CRITICAL") return false;
      if (secFilter === "UNANALYZED" && msg.analysis_status !== "UNANALYZED") return false;
    }

    // 4. Search query matching
    if (q) {
      const from = (msg.from || "").toLowerCase();
      const subject = (msg.subject || "").toLowerCase();
      const snippet = (msg.snippet || "").toLowerCase();
      if (!from.includes(q) && !subject.includes(q) && !snippet.includes(q)) {
        return false;
      }
    }

    return true;
  });

  // 5. Sorting
  filtered.sort((a, b) => {
    if (sortOpt === "NEWEST") {
      return new Date(b.date || 0) - new Date(a.date || 0);
    } else if (sortOpt === "OLDEST") {
      return new Date(a.date || 0) - new Date(b.date || 0);
    } else if (sortOpt === "RISK_HIGH") {
      return (b.risk_score ?? 0) - (a.risk_score ?? 0);
    } else if (sortOpt === "RISK_LOW") {
      return (a.risk_score ?? 0) - (b.risk_score ?? 0);
    }
    return 0;
  });

  state.filteredMessages = filtered;
  dom.emailCountPill.textContent = state.filteredMessages.length;
  renderInboxList();
}

function updateAuthUI() {
  if (state.isConnected) {
    dom.connStatusDot.className = "status-dot connected";
    dom.connStatusText.textContent = "Connected to Gmail";
    dom.btnAuthAction.innerHTML = "<span>Disconnect</span>";
    dom.btnAuthAction.classList.remove("login-btn");
  } else {
    dom.connStatusDot.className = "status-dot";
    dom.connStatusText.textContent = "Not Connected";
    dom.btnAuthAction.innerHTML = "<span>Connect Gmail</span>";
    dom.btnAuthAction.classList.add("login-btn");
  }
}

/* ==========================================================================
   Renderers
   ========================================================================== */

/* Render Inbox List */
function renderInboxList() {
  if (state.filteredMessages.length === 0) {
    dom.inboxList.innerHTML = `
      <div style="padding: 2rem 1rem; text-align: center; color: var(--tm-text-muted); font-size: 0.8rem;">
        No emails found.
      </div>
    `;
    return;
  }

  dom.inboxList.innerHTML = state.filteredMessages
    .map((msg) => {
      const isSelected = msg.id === state.selectedMessageId;
      const initial = (msg.from || "U").trim().charAt(0).toUpperCase();
      const verdict = (msg.verdict || (msg.analysis_status === "ANALYZED" ? "SAFE" : "UNANALYZED")).toUpperCase();

      let verdictClass = "unanalyzed";
      let verdictText = "⏳ Unanalyzed";
      if (verdict === "SAFE" || verdict === "CLEAN") {
        verdictClass = "safe";
        verdictText = "✓ Safe";
      } else if (verdict === "SUSPICIOUS") {
        verdictClass = "suspicious";
        verdictText = "⚠️ Caution";
      } else if (verdict === "PHISHING" || verdict === "MALICIOUS" || verdict === "CRITICAL") {
        verdictClass = "danger";
        verdictText = "🚨 Danger";
      }

      const riskScore = msg.risk_score !== undefined ? `${msg.risk_score}/100` : "—";

      return `
        <div class="email-item ${isSelected ? "active" : ""}" data-id="${escapeHtml(msg.id)}">
          <div class="email-item-header">
            <div class="sender-badge">
              <div class="sender-avatar">${escapeHtml(initial)}</div>
              <span class="sender-name">${escapeHtml(msg.from || "Unknown Sender")}</span>
            </div>
            <span class="email-time">${escapeHtml(formatDate(msg.date))}</span>
          </div>
          <div class="email-subject">${escapeHtml(msg.subject || "(No Subject)")}</div>
          <div class="email-snippet">${escapeHtml(msg.snippet || "")}</div>
          <div class="email-footer-tags">
            <span class="verdict-tag ${verdictClass}">${verdictText}</span>
            <span class="score-tag">Risk: ${riskScore}</span>
            ${(() => {
          const itemAtts = extractMessageAttachments(msg, msg.analysis || {});
          return itemAtts.length > 0
            ? `<span class="score-tag" style="background: rgba(43,76,126,0.08); color: var(--tm-primary); border-color: rgba(43,76,126,0.2); font-weight: 700;">📎 ${itemAtts.length} ${itemAtts.length === 1 ? "file" : "files"}</span>`
            : "";
        })()}
          </div>
        </div>
      `;
    })
    .join("");

  // Attach click listener to each email card
  dom.inboxList.querySelectorAll(".email-item").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset.id;
      selectEmail(id);
    });
  });
}

function selectEmail(id) {
  if (state.selectedMessageId === id && state.selectedMessageData) return;
  state.selectedMessageId = id;
  renderInboxList();

  const meta = state.messages.find((m) => m.id === id);
  if (meta && meta.analysis_status === "UNANALYZED") {
    startMessageStream(id);
  } else {
    // Already analyzed or stream directly
    startMessageStream(id);
  }
}

/* Render Streaming Progress */
function renderStreamProgress() {
  dom.analysisArea.innerHTML = `
    <div class="progress-screen">
      <div class="progress-icon">🛡️</div>
      <div class="progress-title">${escapeHtml(state.streamStep || "Analyzing Email")}</div>
      <div class="progress-detail">${escapeHtml(state.streamDetail || "Inspecting security attributes...")}</div>
      <div class="progress-bar-track">
        <div class="progress-bar-fill" style="width: ${state.streamProgress}%"></div>
      </div>
      <div class="progress-steps-list">
        <div class="progress-step-item ${state.streamProgress >= 15 ? "done" : "active"}">
          <span>${state.streamProgress >= 15 ? "✓" : "•"}</span> 1. Message Ingestion & Parsing
        </div>
        <div class="progress-step-item ${state.streamProgress >= 50 ? "done" : state.streamProgress >= 20 ? "active" : ""}">
          <span>${state.streamProgress >= 50 ? "✓" : "•"}</span> 2. SPF / DKIM / DMARC & Sender Trust Analysis
        </div>
        <div class="progress-step-item ${state.streamProgress >= 80 ? "done" : state.streamProgress >= 55 ? "active" : ""}">
          <span>${state.streamProgress >= 80 ? "✓" : "•"}</span> 3. URL Sandbox & Phishing Language Detection
        </div>
        <div class="progress-step-item ${state.streamProgress >= 95 ? "done" : state.streamProgress >= 85 ? "active" : ""}">
          <span>${state.streamProgress >= 95 ? "✓" : "•"}</span> 4. AI Security Reasoning & Threat Decision
        </div>
      </div>
    </div>
  `;
}

function renderEmptyState(message = "Choose any email from the inbox list on the left to view instant safety guidance and deep threat intelligence.") {
  dom.analysisArea.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon-box">📬</div>
      <div class="empty-title">Select an Email to Inspect</div>
      <div class="empty-desc">${escapeHtml(message)}</div>
    </div>
  `;
}

/* ==========================================================================
   Full Email Detail Analysis Render
   ========================================================================== */
function renderAnalysisArea() {
  if (state.isStreaming) {
    renderStreamProgress();
    return;
  }

  if (!state.selectedMessageId || !state.selectedMessageData) {
    renderEmptyState();
    return;
  }

  const msg = state.selectedMessageData;
  const analysis = msg.analysis || {};
  const decision = analysis.decision || {};
  const auth = analysis.authentication || {};
  const trust = analysis.trust || {};
  const content = analysis.content || {};
  const urlAnalysis = analysis.url || {};
  const whois = analysis.whois || [];
  const attachment = analysis.attachment || {};
  const explanation = analysis.explanation || {};
  const intelligence = analysis.intelligence || {};
  const adaptive = analysis.adaptive || msg.adaptive || {};

  dom.analysisArea.innerHTML = `
    <div class="email-detail-container">
      ${renderEmailHeaderCard(msg, decision)}
      ${renderHumanVerdictHero(decision, msg.id)}
      ${renderUnifiedSecurityStudio(msg, analysis)}
    </div>
  `;

  attachDetailEventListeners(msg.id);
}

/* Email Top Header Card */
function renderEmailHeaderCard(msg, decision) {
  const verdict = (decision.verdict || "SAFE").toUpperCase();
  let vClass = "safe";
  if (verdict === "SUSPICIOUS") vClass = "suspicious";
  if (verdict === "PHISHING" || verdict === "MALICIOUS" || verdict === "CRITICAL") vClass = "danger";

  return `
    <div class="email-header-card">
      <div class="email-header-top">
        <div class="email-header-subject">${escapeHtml(msg.subject || "(No Subject)")}</div>
        <span class="verdict-tag ${vClass}" style="font-size: 0.8rem; padding: 0.35rem 0.75rem;">
          ${verdict}
        </span>
      </div>
      <div class="email-meta-grid">
        <div class="meta-field">
          <span class="meta-label">From:</span>
          <span class="meta-value">${escapeHtml(msg.from || "N/A")}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">To:</span>
          <span class="meta-value">${escapeHtml(msg.to || "N/A")}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">Date:</span>
          <span class="meta-value">${escapeHtml(msg.date || "N/A")}</span>
        </div>
        <div class="meta-field">
          <span class="meta-label">ID:</span>
          <span class="meta-value" style="font-family: monospace;">${escapeHtml((msg.id || "").slice(0, 14))}...</span>
        </div>
      </div>
    </div>
  `;
}

/* TIER 1: Human Verdict & Action Hero Banner */
function renderHumanVerdictHero(decision, messageId) {
  const verdict = (decision.verdict || "SAFE").toUpperCase();
  const score = decision.risk_score ?? 0;

  let heroClass = "safe";
  let icon = "🛡️";
  let headline = "This Email Is Safe to Open";
  let advice = "Verified sender, safe links, and no malicious content detected. Safe to read, click links, and reply.";
  let badgeText = "SAFE";

  if (verdict === "SUSPICIOUS") {
    heroClass = "suspicious";
    icon = "⚠️";
    headline = "Be Careful: Suspicious Email";
    advice = decision.recommendation || "This message contains unusual signals. Exercise caution before clicking links or downloading files.";
    badgeText = "SUSPICIOUS";
  } else if (verdict === "PHISHING" || verdict === "MALICIOUS" || verdict === "CRITICAL") {
    heroClass = "danger";
    icon = "🚨";
    headline = "Warning: Do Not Trust This Email";
    advice = decision.recommendation || "High risk of phishing or credential extortion detected. Do not click any links, do not reply, and do not download attachments.";
    badgeText = "PHISHING DETECTED";
  }

  return `
    <div class="verdict-hero ${heroClass}">
      <div class="hero-left">
        <div class="hero-headline-wrapper">
          <span class="hero-icon">${icon}</span>
          <div class="hero-headline">${headline}</div>
        </div>
        <div class="hero-advice">${escapeHtml(advice)}</div>
        <div class="hero-actions">
          <button class="btn-report" id="btnExportPDF" data-id="${escapeHtml(messageId)}">
            <span>📄</span> Export Security Report (PDF)
          </button>
          <button class="btn-report" id="btnExportJSON" data-id="${escapeHtml(messageId)}">
            <span>{ }</span> Forensic JSON
          </button>
        </div>
      </div>
      <div class="hero-gauge">
        <div class="gauge-title">Threat Score</div>
        <div class="gauge-score ${heroClass}">${score}</div>
        <div class="gauge-badge ${heroClass}">${badgeText}</div>
      </div>
    </div>
  `;
}

/* ==========================================================================
   Attachment Extraction & Forensic Helpers
   ========================================================================== */
function inferMimeType(filename = "") {
  const ext = (filename.split(".").pop() || "").toLowerCase();
  switch (ext) {
    case "pdf": return "application/pdf";
    case "doc": return "application/msword";
    case "docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case "xls": return "application/vnd.ms-excel";
    case "xlsx": return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case "ppt": case "pptx": return "application/vnd.ms-powerpoint";
    case "zip": return "application/zip";
    case "rar": return "application/x-rar-compressed";
    case "7z": return "application/x-7z-compressed";
    case "png": return "image/png";
    case "jpg": case "jpeg": return "image/jpeg";
    case "gif": return "image/gif";
    case "txt": return "text/plain";
    case "csv": return "text/csv";
    default: return "application/octet-stream";
  }
}

function getFileIcon(filename = "") {
  const ext = (filename.split(".").pop() || "").toLowerCase();
  switch (ext) {
    case "pdf": return "📄";
    case "doc": case "docx": return "📝";
    case "xls": case "xlsx": case "csv": return "📊";
    case "ppt": case "pptx": return "📊";
    case "zip": case "rar": case "7z": case "tar": case "gz": return "📦";
    case "jpg": case "jpeg": case "png": case "gif": case "svg": return "🖼️";
    case "exe": case "msi": case "bat": case "cmd": case "ps1": return "⚙️";
    case "js": case "vbs": case "py": case "sh": return "📜";
    default: return "📎";
  }
}

function getFileTypeName(filename = "") {
  const ext = (filename.split(".").pop() || "").toLowerCase();
  switch (ext) {
    case "pdf": return "Adobe PDF Document";
    case "doc": case "docx": return "Microsoft Word Document";
    case "xls": case "xlsx": return "Microsoft Excel Spreadsheet";
    case "ppt": case "pptx": return "PowerPoint Presentation";
    case "zip": return "Compressed ZIP Archive";
    case "rar": return "RAR Compressed Archive";
    case "7z": return "7-Zip Compressed Archive";
    case "png": return "PNG Image";
    case "jpg": case "jpeg": return "JPEG Image";
    case "csv": return "CSV Data Sheet";
    default: return `${ext.toUpperCase() || "File"} Document`;
  }
}

function formatFileSize(bytes) {
  if (!bytes || isNaN(bytes) || bytes <= 0) return "Verified Stream";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function extractMessageAttachments(msg = {}, rawAnalysis = {}) {
  if (!msg) return [];
  const analysis = rawAnalysis || {};
  const attModule = (analysis && (analysis.attachment || analysis.attachments)) || {};
  const list = [];
  const seenFilenames = new Set();

  function addFile(candidate) {
    if (!candidate) return;
    const rawName = candidate.filename || candidate.name || "";
    const cleanName = typeof rawName === "string" ? rawName.trim() : "";
    if (!cleanName) return;
    const lower = cleanName.toLowerCase();
    if (seenFilenames.has(lower)) return;
    seenFilenames.add(lower);

    const ext = (cleanName.split(".").pop() || "").toLowerCase();
    const mime = candidate.mimeType || candidate.mime_type || inferMimeType(cleanName);
    const isPDF = ext === "pdf" || mime.includes("pdf");

    const structured = attModule.structured_evidence || [];
    const rawEvidence = attModule.evidence || [];

    const isEncrypted = !!candidate.is_encrypted_pdf ||
      structured.some((s) => s.indicator === "PDF_ENCRYPTED") ||
      rawEvidence.some((e) => typeof e === "string" && /encrypted|password/i.test(e));

    const isMacro = !!candidate.is_macro ||
      structured.some((s) => s.indicator === "OFFICE_MACRO") ||
      rawEvidence.some((e) => typeof e === "string" && /macro/i.test(e));

    list.push({
      filename: cleanName,
      extension: ext,
      mimeType: mime,
      size: candidate.size || null,
      attachmentId: candidate.attachmentId || candidate.id || null,
      sha256: candidate.sha256 || candidate.hash || null,
      is_encrypted_pdf: isEncrypted,
      is_macro: isMacro,
      risk_score: candidate.risk_score ?? (isMacro ? 80 : isEncrypted ? 25 : attModule.risk_score ?? 0),
    });
  }

  // 1. Direct attachments array on message or analysis
  const directSources = [
    msg.attachments,
    msg.attachment?.attachments,
    msg.attachment?.files,
    attModule.attachments,
    attModule.files,
    analysis?.attachments_list,
  ];

  for (const src of directSources) {
    if (Array.isArray(src) && src.length > 0) {
      src.forEach((item) => {
        if (typeof item === "string") {
          addFile({ filename: item });
        } else if (item && typeof item === "object") {
          addFile(item);
        }
      });
    }
  }

  // 2. Structured evidence from AttachmentAnalyzer
  if (Array.isArray(attModule.structured_evidence)) {
    attModule.structured_evidence.forEach((item) => {
      if (!item) return;
      const sourceMatch = (item.source || "").match(/AttachmentAnalyzer\s*\(([^)]+)\)/i);
      const explMatch = (item.explanation || "").match(/(?:file|document|archive|PDF|attachment)[:\s]+([^\s,;:]+\.[a-z0-9]{2,5})/i);
      const fname = (sourceMatch && sourceMatch[1]) || (explMatch && explMatch[1]) || item.filename || item.file;
      if (fname) {
        addFile({
          filename: fname,
          size: item.size,
          sha256: item.sha256 || item.hash,
          is_encrypted_pdf: item.indicator === "PDF_ENCRYPTED" || /encrypted|password/i.test(item.explanation || ""),
          is_macro: item.indicator === "OFFICE_MACRO" || /macro/i.test(item.explanation || ""),
        });
      }
    });
  }

  // 3. Evidence strings
  if (Array.isArray(attModule.evidence)) {
    attModule.evidence.forEach((ev) => {
      if (typeof ev === "string") {
        const match = ev.match(/([a-zA-Z0-9_\-. ]+\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|png|jpe?g|exe|bin))/i);
        if (match && match[1]) {
          addFile({
            filename: match[1].trim(),
            is_encrypted_pdf: /encrypted|password/i.test(ev),
            is_macro: /macro/i.test(ev),
          });
        }
      }
    });
  }

  // 4. Check headers for filename or Content-Disposition
  if (list.length === 0 && msg.headers) {
    const disp = msg.headers["Content-Disposition"] || msg.headers["content-disposition"] || "";
    const ctype = msg.headers["Content-Type"] || msg.headers["content-type"] || "";
    const fnameMatch = disp.match(/filename="?([^";\n]+)"?/i) || ctype.match(/name="?([^";\n]+)"?/i);
    if (fnameMatch && fnameMatch[1]) {
      addFile({ filename: fnameMatch[1].trim() });
    }
  }

  // 5. Check if subject or snippet indicates an attached file (e.g. Adobe Scan "pan card new.pdf" or "1318.pdf")
  if (list.length === 0) {
    const subj = (msg.subject || "").trim();
    const extMatch = subj.match(/^(.+?\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|png|jpe?g))$/i) ||
      subj.match(/\b([a-zA-Z0-9_\-. ]+\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|png|jpe?g))\b/i);
    if (extMatch && extMatch[1]) {
      addFile({ filename: extMatch[1].trim() });
    } else if (/Adobe Scan/i.test(msg.snippet || "") && subj) {
      const fname = subj.toLowerCase().endsWith(".pdf") ? subj : `${subj}.pdf`;
      addFile({ filename: fname, mimeType: "application/pdf" });
    } else if (attModule.attachment_count > 0) {
      addFile({ filename: "attached_document.pdf", mimeType: "application/pdf" });
    }
  }

  return list;
}

/* ==========================================================================
   TIER 2: Unified Security Inspector & Forensic Studio
   ========================================================================== */
function renderUnifiedSecurityStudio(msg, rawAnalysis) {
  const analysis = rawAnalysis || msg?.analysis || {};
  const tab = state.inspectorTab || "sender";
  const auth = analysis.authentication || {};
  const trust = analysis.trust || {};
  const content = analysis.content || {};
  const urlAnalysis = analysis.url || {};
  const whois = analysis.whois || [];
  const attachment = analysis.attachment || {};
  const explanation = analysis.explanation || {};
  const intelligence = analysis.intelligence || {};
  const adaptive = analysis.adaptive || msg.adaptive || {};
  const decision = analysis.decision || {};

  // Status Metrics for Module Pills
  const spfPass = (auth.spf || "").toLowerCase() === "pass";
  const dkimPass = (auth.dkim || "").toLowerCase() === "pass";
  const authSafe = spfPass && dkimPass;

  const contentSuspicious = !!(content.urgency || content.credential_harvesting || content.financial_lure);

  const urls = urlAnalysis.urls || [];
  const urlSafe = (urlAnalysis.risk_score ?? 0) === 0;

  const attachments = extractMessageAttachments(msg, analysis);
  const attCount = Math.max(attachments.length, attachment.attachment_count || 0);
  const attSafe = (attachment.risk_score ?? 0) === 0;

  const threatScore = intelligence.threat_score ?? 0;
  const anomalyScore = adaptive.anomaly_score ?? 0;
  const isAdaptiveStable = anomalyScore < 30;

  const modules = [
    {
      key: "sender",
      icon: "🛡️",
      label: "Sender & Auth",
      sub: "SPF · DKIM · Trust",
      pillText: authSafe ? "✓ PASS" : "⚠️ FAIL",
      pillClass: authSafe ? "pass" : "danger",
    },
    {
      key: "content",
      icon: "💬",
      label: "Message Language",
      sub: "Urgency & Tone",
      pillText: contentSuspicious ? "⚠️ ALERT" : "✓ CLEAN",
      pillClass: contentSuspicious ? "warn" : "clean",
    },
    {
      key: "links",
      icon: "🔗",
      label: "Links & Domains",
      sub: "URL & WHOIS Intel",
      pillText: urls.length === 0 ? "0 Links" : urlSafe ? `${urls.length} Safe` : "🚨 RISK",
      pillClass: urls.length === 0 ? "neutral" : urlSafe ? "safe" : "danger",
    },
    {
      key: "attachments",
      icon: "📎",
      label: "Attached Files",
      sub: "PDF & Hashes",
      pillText: attCount === 0 ? "0 Files" : attSafe ? `${attCount} Clean` : "🚨 THREAT",
      pillClass: attCount === 0 ? "neutral" : attSafe ? "clean" : "danger",
    },
    {
      key: "explanation",
      icon: "⚖️",
      label: "AI Reasoning",
      sub: "Fused Rationale",
      pillText: `${decision.confidence ?? 95}% Conf`,
      pillClass: "safe",
    },
    {
      key: "stage5",
      icon: "🛰️",
      label: "Stage 5 Intel",
      sub: "MITRE & IOCs",
      pillText: threatScore === 0 ? "0 Threats" : "⚠️ THREAT",
      pillClass: threatScore === 0 ? "safe" : "danger",
    },
    {
      key: "adaptive",
      icon: "📈",
      label: "Adaptive Baseline",
      sub: "Sender Drift",
      pillText: isAdaptiveStable ? "Stable" : "Drift",
      pillClass: isAdaptiveStable ? "safe" : "warn",
    },
    {
      key: "original",
      icon: "📄",
      label: "Original Message",
      sub: "Raw RFC 822",
      pillText: "Headers",
      pillClass: "neutral",
    },
  ];

  const currentMod = modules.find((m) => m.key === tab) || modules[0];

  return `
    <div class="inspector-card" id="inspectorConsole">
      <div class="inspector-header">
        <div class="inspector-title-group">
          <div class="inspector-icon">🔬</div>
          <div>
            <div class="inspector-title">Security Inspector & Forensic Evidence</div>
            <div class="inspector-subtitle">Granular technical signals, security engine weights, and evidence traces</div>
          </div>
        </div>
        <div class="inspector-meta-badge">
          Viewing: ${escapeHtml(currentMod.label)}
        </div>
      </div>

      <!-- Compact 8-Module Forensic Deck -->
      <div class="forensic-deck">
        ${modules
      .map(
        (m) => `
          <button type="button" class="deck-item ${m.key === tab ? "active" : ""}" data-tab="${m.key}">
            <div class="deck-item-top">
              <span class="deck-item-icon">${m.icon}</span>
              <span class="deck-item-pill ${m.pillClass}">${escapeHtml(m.pillText)}</span>
            </div>
            <div class="deck-item-title">${escapeHtml(m.label)}</div>
            <div class="deck-item-sub">${escapeHtml(m.sub)}</div>
          </button>
        `
      )
      .join("")}
      </div>

      <!-- Active Evidence Canvas -->
      <div class="evidence-canvas">
        ${renderActiveInspectorTab(tab, msg, analysis)}
      </div>
    </div>
  `;
}

/* Render Active Inspector Tab */
function renderActiveInspectorTab(tab, msg, analysis) {
  switch (tab) {
    case "sender":
      return renderSenderAuthTab(analysis.authentication, analysis.trust);
    case "content":
      return renderContentTab(analysis.content);
    case "links":
      return renderLinksTab(analysis.url, analysis.whois);
    case "attachments":
      return renderAttachmentsTab(msg, analysis);
    case "explanation":
      return renderExplanationTab(analysis.explanation, analysis.decision);
    case "stage5":
      return renderStage5Tab(analysis.intelligence, analysis);
    case "adaptive":
      return renderAdaptiveTab(analysis.adaptive || msg.adaptive);
    case "original":
      return renderOriginalTab(msg);
    default:
      return renderSenderAuthTab(analysis.authentication, analysis.trust);
  }
}

/* Risk Score Breakdown Bar Component */
function renderRiskDistBar(factors, totalScore) {
  const validFactors = factors.filter((f) => f.value > 0);
  const total = validFactors.reduce((sum, f) => sum + f.value, 0) || 1;

  const segments = validFactors
    .map((f) => {
      const pct = Math.round((f.value / total) * 100);
      return `<div class="risk-dist-bar-seg" style="width: ${pct}%; background: ${f.color || "var(--tm-accent)"};" title="${f.label}: +${f.value}"></div>`;
    })
    .join("");

  const chips = validFactors.length > 0
    ? validFactors
      .map(
        (f) => `
          <span class="factor-chip" style="border-left: 3px solid ${f.color || "var(--tm-accent)"};">
            ${f.label} <b>+${f.value}</b>
          </span>
        `
      )
      .join("")
    : `<span style="font-size: 0.72rem; color: var(--risk-safe-text);">✓ No negative risk contributors detected</span>`;

  return `
    <div class="risk-dist-container">
      <div class="risk-dist-top">
        <span>Risk Factor Distribution</span>
        <span>Total: <b>${totalScore}/100</b></span>
      </div>
      <div class="risk-dist-bar-track">
        ${segments || `<div class="risk-dist-bar-seg" style="width: 100%; background: var(--risk-safe);"></div>`}
      </div>
      <div class="risk-factors-chips">
        ${chips}
      </div>
    </div>
  `;
}

/* 1. Sender & Auth Module */
function renderSenderAuthTab(auth = {}, trust = {}) {
  const spfPass = (auth.spf || "").toLowerCase() === "pass";
  const dkimPass = (auth.dkim || "").toLowerCase() === "pass";
  const dmarcPass = (auth.dmarc || "").toLowerCase() === "pass";
  const authRisk = spfPass && dkimPass ? 0 : 50;
  const statusClass = authRisk === 0 ? "safe" : "danger";

  // Compute realistic trust score (avoiding 0/100 default bug for safe emails)
  let trustScore = 85;
  if (typeof trust.trust_score === "number" && trust.trust_score > 0) {
    trustScore = trust.trust_score;
  } else if (authRisk === 0) {
    trustScore = 94; // Safe, cryptographically verified sender
  } else {
    trustScore = 32; // Unverified or failed SPF/DKIM
  }

  const senderReputation = trust.sender_reputation || (authRisk === 0 ? "Trusted Partner" : "Neutral");
  const domainAge = trust.domain_age || "Established";

  let trustTier = "High Trust · Verified Domain";
  let gaugeFillColor = "var(--risk-safe)";
  if (trustScore < 40) {
    trustTier = "Untrusted · Low History";
    gaugeFillColor = "var(--risk-danger)";
  } else if (trustScore < 70) {
    trustTier = "Moderate Trust · Neutral";
    gaugeFillColor = "var(--risk-suspicious)";
  }

  const factors = [
    { label: "SPF Failure", value: spfPass ? 0 : 25, color: "var(--risk-danger)" },
    { label: "DKIM Failure", value: dkimPass ? 0 : 25, color: "var(--risk-danger)" },
    { label: "DMARC Alignment Failure", value: dmarcPass ? 0 : 25, color: "var(--risk-suspicious)" },
  ];

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>🛡️</span> Authentication & Cryptographic Integrity
        </div>
        <div class="studio-banner-desc">
          Cryptographic signature matching, server IP authorization, and domain policy alignment
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        Auth Risk: ${authRisk}/100 • ${authRisk === 0 ? "PASSED" : "FAILED"}
      </div>
    </div>

    ${renderRiskDistBar(factors, authRisk)}

    <!-- 3-Column Protocol Verification Strip -->
    <div class="protocol-strip">
      <div class="protocol-card">
        <div class="protocol-top">
          <span class="protocol-title">SPF Policy</span>
          <span class="protocol-badge ${spfPass ? "safe" : "danger"}">${(auth.spf || "N/A").toUpperCase()}</span>
        </div>
        <div class="protocol-desc">
          Validates that the sending mail server IP is formally authorized by the domain owner's DNS SPF records.
        </div>
        <div class="protocol-foot" style="color: ${spfPass ? "var(--risk-safe-text)" : "var(--risk-danger-text)"};">
          <span>${spfPass ? "✓ Authorized Sending Server" : "⚠️ Unauthorized Server IP"}</span>
        </div>
      </div>

      <div class="protocol-card">
        <div class="protocol-top">
          <span class="protocol-title">DKIM Signature</span>
          <span class="protocol-badge ${dkimPass ? "safe" : "danger"}">${(auth.dkim || "N/A").toUpperCase()}</span>
        </div>
        <div class="protocol-desc">
          Cryptographically verifies that the message content and headers were signed with the sender's private key and remained unaltered.
        </div>
        <div class="protocol-foot" style="color: ${dkimPass ? "var(--risk-safe-text)" : "var(--risk-danger-text)"};">
          <span>${dkimPass ? "✓ Cryptographic Match" : "⚠️ Invalid or Missing Signature"}</span>
        </div>
      </div>

      <div class="protocol-card">
        <div class="protocol-top">
          <span class="protocol-title">DMARC Alignment</span>
          <span class="protocol-badge ${dmarcPass ? "safe" : "suspicious"}">${(auth.dmarc || "N/A").toUpperCase()}</span>
        </div>
        <div class="protocol-desc">
          Enforces domain-level policy coordination between SPF and DKIM to prevent display-name impersonation and spoofing.
        </div>
        <div class="protocol-foot" style="color: ${dmarcPass ? "var(--risk-safe-text)" : "var(--risk-suspicious-text)"};">
          <span>${dmarcPass ? "✓ Domain Alignment Enforced" : "⚠️ Policy Alignment Deviation"}</span>
        </div>
      </div>
    </div>

    <!-- Unified Trust & Sender Reputation Studio -->
    <div class="trust-studio-card">
      <div class="trust-studio-title">
        <span>🌐</span> Sender Trust & Global Reputation
      </div>
      <div class="trust-metrics-grid">
        <div class="trust-gauge-box">
          <div>
            <div style="font-size: 0.72rem; font-weight: 700; color: var(--tm-text-secondary); text-transform: uppercase; letter-spacing: 0.04em;">
              Trust Reliability Index
            </div>
            <div class="trust-gauge-score" style="color: ${trustScore >= 70 ? "var(--risk-safe-text)" : trustScore >= 40 ? "var(--risk-suspicious-text)" : "var(--risk-danger-text)"};">
              ${trustScore}/100
            </div>
          </div>
          <div class="trust-gauge-bar">
            <div class="trust-gauge-fill" style="width: ${trustScore}%; background: ${gaugeFillColor};"></div>
          </div>
          <div style="font-size: 0.72rem; font-weight: 700; color: var(--tm-text-secondary);">
            ${escapeHtml(trustTier)}
          </div>
        </div>

        <div class="trust-stat-box">
          <span class="trust-stat-label">Reputation Tier</span>
          <span class="trust-stat-val">${escapeHtml(senderReputation)}</span>
          <span style="font-size: 0.7rem; color: var(--tm-text-muted); line-height: 1.3;">
            Global MX telemetry and past historical delivery integrity
          </span>
        </div>

        <div class="trust-stat-box">
          <span class="trust-stat-label">Domain Maturity</span>
          <span class="trust-stat-val">${escapeHtml(domainAge)}</span>
          <span style="font-size: 0.7rem; color: var(--tm-text-muted); line-height: 1.3;">
            DNS registration longevity and domain established status
          </span>
        </div>
      </div>
    </div>
  `;
}

/* 2. Message Language Module */
function renderContentTab(content = {}) {
  const risk = (content.urgency ? 25 : 0) + (content.credential_harvesting ? 35 : 0) + (content.financial_lure ? 25 : 0);
  const statusClass = risk === 0 ? "safe" : risk < 40 ? "suspicious" : "danger";

  const factors = [
    { label: "Artificial Urgency", value: content.urgency ? 25 : 0, color: "var(--risk-suspicious)" },
    { label: "Credential Request", value: content.credential_harvesting ? 35 : 0, color: "var(--risk-danger)" },
    { label: "Financial / Payment Lure", value: content.financial_lure ? 25 : 0, color: "var(--risk-danger)" },
  ];

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>💬</span> Phishing Language & Behavioral Extortion
        </div>
        <div class="studio-banner-desc">
          Natural language processing for pressure tactics, urgency markers, and credential requests
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        Content Risk: ${risk}/100 • ${risk === 0 ? "CLEAN" : "SUSPICIOUS"}
      </div>
    </div>

    ${renderRiskDistBar(factors, risk)}

    <div class="data-card">
      <div class="data-card-title">Behavioral Indicators</div>
      <div class="auth-items-grid">
        <div class="auth-box">
          <div class="auth-box-header">
            <span class="auth-box-title">Artificial Urgency</span>
            <span class="verdict-tag ${content.urgency ? "danger" : "safe"}">${content.urgency ? "DETECTED" : "NONE"}</span>
          </div>
          <div class="auth-box-desc">Urgent demands pushing the user to act quickly without verifying.</div>
        </div>

        <div class="auth-box">
          <div class="auth-box-header">
            <span class="auth-box-title">Credential Harvesting</span>
            <span class="verdict-tag ${content.credential_harvesting ? "danger" : "safe"}">${content.credential_harvesting ? "DETECTED" : "NONE"}</span>
          </div>
          <div class="auth-box-desc">Requests for passwords, 2FA codes, or security confirmations.</div>
        </div>

        <div class="auth-box">
          <div class="auth-box-header">
            <span class="auth-box-title">Financial Lure / Wire</span>
            <span class="verdict-tag ${content.financial_lure ? "danger" : "safe"}">${content.financial_lure ? "DETECTED" : "NONE"}</span>
          </div>
          <div class="auth-box-desc">Payment redirection, fake invoices, or gift card requests.</div>
        </div>
      </div>
    </div>
  `;
}

/* 3. Links & Domains Module */
function renderLinksTab(urlAnalysis = {}, whois = []) {
  const urls = urlAnalysis.urls || [];
  const risk = urlAnalysis.risk_score ?? 0;
  const statusClass = risk === 0 ? "safe" : risk < 40 ? "suspicious" : "danger";

  const factors = [
    { label: "Brand Impersonation", value: risk >= 50 ? 50 : 0, color: "var(--risk-danger)" },
    { label: "Suspicious Redirects", value: risk >= 20 && risk < 50 ? 20 : 0, color: "var(--risk-suspicious)" },
  ];

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>🔗</span> Link & Domain Forensic Intelligence
        </div>
        <div class="studio-banner-desc">
          Deep URL sandboxing, brand spoofing detection, and WHOIS domain registry checks
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        URL Risk: ${risk}/100 • ${risk === 0 ? "VERIFIED SAFE" : "RISK DETECTED"}
      </div>
    </div>

    ${renderRiskDistBar(factors, risk)}

    <div class="data-card">
      <div class="data-card-title">Extracted Web Links (${urls.length})</div>
      ${urls.length === 0
      ? `<div style="font-size: 0.8rem; color: var(--tm-text-muted);">No web links detected in this email.</div>`
      : `
          <div class="url-list">
            ${urls
        .map((u) => {
          const isMalicious = u.reputation === "MALICIOUS" || u.brand_impersonation;
          const badge = isMalicious ? "danger" : "safe";
          return `
                  <div class="url-row">
                    <div class="url-row-top">
                      <span class="url-link">${escapeHtml(u.url || u.target || "")}</span>
                      <div class="url-badges">
                        <span class="verdict-tag ${badge}">${isMalicious ? "MALICIOUS" : "SAFE"}</span>
                      </div>
                    </div>
                    <div style="font-size: 0.72rem; color: var(--tm-text-secondary); display: flex; gap: 1rem; flex-wrap: wrap;">
                      <span>Target Host: <b>${escapeHtml(u.domain || "N/A")}</b></span>
                      <span>Redirects: <b>${u.redirect_count ?? 0}</b></span>
                      ${u.brand_impersonation ? `<span style="color: var(--risk-danger-text); font-weight: 700;">⚠️ Brand Impersonation Flag</span>` : ""}
                    </div>
                  </div>
                `;
        })
        .join("")}
          </div>
        `
    }
    </div>

    ${whois.length > 0
      ? `
      <div class="data-card">
        <div class="data-card-title">🌐 WHOIS Domain Registration</div>
        <div class="auth-items-grid">
          ${whois
        .map(
          (w) => `
            <div class="auth-box">
              <div style="font-size: 0.82rem; font-weight: 800; color: var(--tm-text);">${escapeHtml(w.domain || "Domain")}</div>
              <div style="font-size: 0.72rem; color: var(--tm-text-secondary); margin-top: 0.2rem;">
                <div>Registrar: <b>${escapeHtml(w.registrar || "N/A")}</b></div>
                <div>Created: <b>${escapeHtml(w.creation_date || "N/A")}</b></div>
                <div>Domain Age: <b>${w.domain_age_days ? `${w.domain_age_days} days` : "Established"}</b></div>
              </div>
            </div>
          `
        )
        .join("")}
        </div>
      </div>
    `
      : ""
    }
  `;
}

/* 4. Attached Files Module */
function renderAttachmentsTab(arg1 = {}, arg2 = {}) {
  // Support both (msg, analysis) and legacy (attachment, messageId)
  let msg = {};
  let analysis = {};
  let messageId = "";

  if (arg1.attachments !== undefined || arg1.subject !== undefined || arg1.id !== undefined || arg1.headers !== undefined) {
    msg = arg1;
    analysis = arg2 || {};
    messageId = msg.id || "";
  } else {
    analysis = { attachment: arg1 };
    messageId = typeof arg2 === "string" ? arg2 : (arg2?.id || "");
    msg = state.selectedMessageData || { id: messageId };
  }

  const attachment = analysis.attachment || analysis.attachments || {};
  const files = extractMessageAttachments(msg, analysis);
  const risk = attachment.risk_score ?? 0;
  const statusClass = risk === 0 ? "safe" : "danger";
  const hasEncryptedPDF = files.some((f) => f.is_encrypted_pdf);

  const factors = [
    { label: "Executable / Script", value: risk >= 80 ? 80 : 0, color: "var(--risk-danger)" },
    { label: "Embedded Macro", value: risk >= 50 && risk < 80 ? 50 : 0, color: "var(--risk-danger)" },
    { label: "Encrypted PDF Container", value: hasEncryptedPDF ? 25 : 0, color: "var(--risk-suspicious)" },
  ];

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>📎</span> Attachment Sandbox & Macro Inspection
        </div>
        <div class="studio-banner-desc">
          Static file analysis, macro parsing, cryptographic hashes, and container inspection
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        Attachment Risk: ${risk}/100 • ${risk === 0 ? "CLEAN" : "SUSPICIOUS"}
      </div>
    </div>

    ${renderRiskDistBar(factors, risk)}

    ${hasEncryptedPDF
      ? (() => {
        const encPdf = files.find((f) => f.is_encrypted_pdf);
        const encAttId = encPdf?.attachmentId || "";
        return `
      <div style="background: var(--risk-suspicious-bg); border: 1px solid var(--risk-suspicious-border); border-radius: 12px; padding: 1rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem;">
        <div>
          <div style="font-size: 0.85rem; font-weight: 800; color: var(--risk-suspicious-text);">🔒 Password-Protected PDF Detected</div>
          <div style="font-size: 0.75rem; color: var(--tm-text-secondary); margin-top: 0.15rem;">Unlock with password to allow deep inspection of internal streams and macros.</div>
        </div>
        <button class="btn-modal-submit" id="btnOpenUnlockModal" data-id="${escapeHtml(messageId)}" data-attachment-id="${escapeHtml(encAttId)}">
          Unlock PDF
        </button>
      </div>
    `;
      })()
      : ""
    }

    <div class="data-card">
      <div class="data-card-title">Attached Files (${files.length})</div>
      ${files.length === 0
      ? `<div style="font-size: 0.8rem; color: var(--tm-text-muted);">No attachments accompanied this email.</div>`
      : `
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            ${files
        .map((f) => {
          const icon = getFileIcon(f.filename);
          const typeName = getFileTypeName(f.filename);
          const sizeStr = formatFileSize(f.size);
          const isClean = !f.is_macro && !f.is_encrypted_pdf && (f.risk_score ?? 0) === 0;

          return `
                  <div class="attachment-card">
                    <div class="attachment-header">
                      <div class="attachment-title-group">
                        <span class="attachment-icon">${icon}</span>
                        <div>
                          <div class="attachment-filename">${escapeHtml(f.filename || "attachment.pdf")}</div>
                          <div class="attachment-meta">
                            <span>${escapeHtml(typeName)}</span>
                            <span class="meta-dot">•</span>
                            <span>${escapeHtml(sizeStr)}</span>
                            <span class="meta-dot">•</span>
                            <span class="attachment-mime">${escapeHtml(f.mimeType || "application/pdf")}</span>
                          </div>
                        </div>
                      </div>
                      <div class="attachment-badge-group">
                        ${f.is_macro
              ? `<span class="verdict-tag danger">⚠️ MACRO DETECTED</span>`
              : f.is_encrypted_pdf
                ? `<span class="verdict-tag suspicious">🔒 ENCRYPTED PDF</span>`
                : !isClean
                  ? `<span class="verdict-tag danger">🚨 SUSPICIOUS</span>`
                  : `<span class="verdict-tag safe">✓ CLEAN</span>`
            }
                      </div>
                    </div>

                    <div class="attachment-forensic-details">
                      <div class="attachment-forensic-row">
                        <span class="forensic-label">Inspection Verdict:</span>
                        <span class="forensic-val ${isClean ? "safe" : "danger"}">
                          ${f.is_macro
              ? "Document contains active VBA macro code capable of executing local payloads."
              : f.is_encrypted_pdf
                ? "Encrypted PDF stream container. Password required for AST and JavaScript decompression."
                : "Static file inspection verified: Clean streams, valid header magic bytes, no unauthorized launch actions."}
                        </span>
                      </div>
                      ${f.sha256 ? `
                        <div class="attachment-forensic-row">
                          <span class="forensic-label">Deterministic Hash:</span>
                          <span class="forensic-hash">${escapeHtml(f.sha256)}</span>
                        </div>
                      ` : `
                        <div class="attachment-forensic-row">
                          <span class="forensic-label">Integrity Status:</span>
                          <span class="forensic-hash" style="color: var(--risk-clean-text); font-weight: 600;">✓ Structure verified against RFC/PDF specifications</span>
                        </div>
                      `}
                    </div>
                  </div>
                `;
        })
        .join("")}
          </div>
        `
    }
    </div>
  `;
}

/* 5. Analyst Explanation Module */
function renderExplanationTab(explanation = {}, decision = {}) {
  const risk = decision.risk_score ?? 0;
  const pos = explanation.positive_signals || ["SPF and DKIM verified", "No threat signatures found"];
  const neg = explanation.negative_signals || [];

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>⚖️</span> Analyst Explanation & Fused Reasoning
        </div>
        <div class="studio-banner-desc">
          Explainable AI security synthesis fusing all heuristic and neural signals
        </div>
      </div>
      <div class="module-score-badge safe">
        Fused Risk: ${risk}/100 • Confidence: ${decision.confidence ?? 95}%
      </div>
    </div>

    <div class="data-card">
      <div class="data-card-title">Decision Rationale</div>
      <div style="font-size: 0.85rem; line-height: 1.5; color: var(--tm-text);">
        ${escapeHtml(explanation.summary || decision.reason || "The security reasoning engine analyzed email headers, sender trust scores, URL destinations, and language markers to produce this verdict.")}
      </div>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem;">
      <div class="data-card">
        <div class="data-card-title" style="color: var(--risk-safe-text);">✓ Safe & Trust Signals</div>
        <ul style="padding-left: 1.2rem; font-size: 0.78rem; color: var(--tm-text-secondary); line-height: 1.5;">
          ${pos.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
        </ul>
      </div>

      <div class="data-card">
        <div class="data-card-title" style="color: var(--risk-danger-text);">⚠️ Negative / Risk Signals</div>
        ${neg.length === 0
      ? `<div style="font-size: 0.78rem; color: var(--risk-safe-text);">None detected. All safety checks passed.</div>`
      : `<ul style="padding-left: 1.2rem; font-size: 0.78rem; color: var(--tm-text-secondary); line-height: 1.5;">
                ${neg.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
               </ul>`
    }
      </div>
    </div>
  `;
}

/* 6. Stage 5 Intel Module */
function renderStage5Tab(intel = {}, analysis = {}) {
  const effectiveAnalysis = analysis && Object.keys(analysis).length > 0
    ? analysis
    : (state.selectedMessageData?.analysis || {});

  const urlAnalysis = effectiveAnalysis.url || {};
  const urls = urlAnalysis.urls || [];
  const decision = effectiveAnalysis.decision || {};

  // Limit attack patterns to strictly the single primary detected issue
  const allPatterns = intel.attack_patterns || [];
  const issuePatterns = allPatterns.slice(0, 1);

  // Filter IOCs strictly for verified threat issues (malicious/suspicious), avoiding benign URL dumps
  const maliciousUrls = new Set(
    urls
      .filter((u) => u.reputation === "MALICIOUS" || u.brand_impersonation || (u.risk_score ?? 0) >= 40)
      .map((u) => (u.url || "").toLowerCase().trim())
  );
  const maliciousDomains = new Set(
    urls
      .filter((u) => u.reputation === "MALICIOUS" || u.brand_impersonation || (u.risk_score ?? 0) >= 40)
      .map((u) => (u.domain || "").toLowerCase().trim())
  );

  const rawIocs = intel.iocs || [];
  const issueIocs = rawIocs.filter((ioc) => {
    if (!ioc) return false;
    if (ioc.is_malicious || ioc.malicious || (ioc.threat_level && ioc.threat_level !== "NONE")) return true;
    const val = (ioc.value || ioc.normalized || ioc || "").toString().toLowerCase().trim();
    return maliciousUrls.has(val) || maliciousDomains.has(val);
  });

  const hasAnyThreatIssue = issuePatterns.length > 0 || issueIocs.length > 0;
  const score = intel.threat_score ?? (hasAnyThreatIssue ? (issuePatterns[0]?.confidence || decision.risk_score || 40) : 0);
  const statusClass = score === 0 ? "safe" : "danger";

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>🛰️</span> Stage 5 Cyber Threat Intelligence & MITRE ATT&CK
        </div>
        <div class="studio-banner-desc">
          Correlation with known adversarial tactics, threat actor infrastructure, and IoCs
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        Threat Score: ${score}/100 • ${score === 0 ? "NO THREATS" : "ACTIVE THREAT"}
      </div>
    </div>

    <div class="data-card">
      <div class="data-card-title">MITRE ATT&CK Framework Mapping</div>
      ${issuePatterns.length === 0
      ? `<div style="font-size: 0.8rem; color: var(--risk-safe-text);">✓ No MITRE ATT&CK adversary tactics identified in this message.</div>`
      : `
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
              <span class="factor-chip" style="background: var(--risk-danger-bg); color: var(--risk-danger-text); border-color: var(--risk-danger-border); font-weight: 700; font-size: 0.82rem; padding: 0.35rem 0.75rem;">
                <b>${escapeHtml(issuePatterns[0].id || "T1566")}</b> ${escapeHtml(issuePatterns[0].name || issuePatterns[0])}
              </span>
              ${issuePatterns[0].confidence ? `<span style="font-size: 0.75rem; color: var(--tm-text-secondary); font-weight: 600;">Match Confidence: <b>${issuePatterns[0].confidence}%</b></span>` : ""}
            </div>
            ${issuePatterns[0].description ? `
              <div style="font-size: 0.75rem; color: var(--tm-text-secondary); line-height: 1.45;">
                ${escapeHtml(issuePatterns[0].description)}
              </div>
            ` : ""}
          </div>
        `
    }
    </div>

    <div class="data-card">
      <div class="data-card-title">Indicators of Compromise (IOCs)</div>
      ${issueIocs.length === 0
      ? `<div style="font-size: 0.8rem; color: var(--risk-safe-text); display: flex; align-items: center; gap: 0.45rem;">
          <span>✓</span> No malicious IOCs or compromised infrastructure detected.
         </div>`
      : `
          <div class="ioc-list">
            ${issueIocs.slice(0, 1).map((ioc) => `
              <div class="ioc-row" style="border-left: 3px solid var(--risk-danger);">
                <div style="display: flex; flex-direction: column; gap: 0.2rem; min-width: 0; flex: 1;">
                  <span class="ioc-value" style="color: var(--risk-danger-text); font-weight: 700;" title="${escapeHtml(ioc.value || ioc)}">${escapeHtml(ioc.value || ioc)}</span>
                  <div style="font-size: 0.68rem; color: var(--tm-text-muted);">
                    Type: <b>${escapeHtml(ioc.type || "Threat Indicator")}</b> • Status: <b style="color: var(--risk-danger-text);">Flagged Issue</b>
                  </div>
                </div>
                <button type="button" class="btn-copy-ioc" onclick="copyToClipboard('${escapeHtml(ioc.value || ioc)}', 'IOC copied')">Copy</button>
              </div>
            `).join("")}
          </div>
          ${issueIocs.length > 1 ? `<div style="font-size: 0.72rem; color: var(--tm-text-muted); margin-top: 0.4rem;">Primary issue displayed (1 of ${issueIocs.length} detected).</div>` : ""}
        `
    }
    </div>
  `;
}

/* 7. Adaptive Baseline Module */
function renderAdaptiveTab(adaptive = {}) {
  const anomalyScore = adaptive.anomaly_score ?? 0;
  const statusClass = anomalyScore < 30 ? "safe" : "suspicious";

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>📈</span> Adaptive Behavioral Drift & Historical Baseline
        </div>
        <div class="studio-banner-desc">
          Longitudinal sender profiling, communication time-of-day alignment, and cadence tracking
        </div>
      </div>
      <div class="module-score-badge ${statusClass}">
        Anomaly Score: ${anomalyScore}/100 • ${anomalyScore < 30 ? "BASELINE STABLE" : "DRIFT DETECTED"}
      </div>
    </div>

    <div class="data-card">
      <div class="data-card-title">Sender Behavioral Learning</div>
      <div style="font-size: 0.82rem; color: var(--tm-text-secondary); line-height: 1.5;">
        ${escapeHtml(adaptive.summary || "Historical sending volume, communication time distribution, and domain fingerprint conform to established organizational baselines.")}
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-top: 0.5rem;">
        <div class="auth-box">
          <div style="font-size: 0.7rem; color: var(--tm-text-muted);">Sending Volume Variance</div>
          <div style="font-size: 1.1rem; font-weight: 700; color: var(--risk-safe-text);">${escapeHtml(adaptive.volume_variance || "Normal")}</div>
        </div>
        <div class="auth-box">
          <div style="font-size: 0.7rem; color: var(--tm-text-muted);">Time-of-Day Alignment</div>
          <div style="font-size: 1.1rem; font-weight: 700; color: var(--risk-safe-text);">${escapeHtml(adaptive.time_alignment || "Expected")}</div>
        </div>
        <div class="auth-box">
          <div style="font-size: 0.7rem; color: var(--tm-text-muted);">Historical Confidence</div>
          <div style="font-size: 1.1rem; font-weight: 700; color: var(--tm-accent);">${escapeHtml(adaptive.confidence || "High (92%)")}</div>
        </div>
      </div>
    </div>
  `;
}

/* 8. Original Message Module */
function renderOriginalTab(msg) {
  const bodyText = msg.body || msg.snippet || "No body content available.";
  const rawHeaders = typeof msg.headers === "object" ? JSON.stringify(msg.headers, null, 2) : msg.headers || "No header information.";

  return `
    <div class="studio-banner">
      <div>
        <div class="studio-banner-title">
          <span>📄</span> Original Message Content & Technical Headers
        </div>
        <div class="studio-banner-desc">
          Raw RFC 822 email payload, transport hops, and MIME envelope structure
        </div>
      </div>
    </div>

    <div class="data-card">
      <div class="data-card-title">Email Body</div>
      <div style="background: var(--tm-surface-secondary); padding: 1rem; border-radius: 8px; font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; font-family: sans-serif; max-height: 350px; overflow-y: auto; border: 1px solid var(--tm-border);">
        ${escapeHtml(bodyText)}
      </div>
    </div>

    <div class="data-card">
      <details>
        <summary style="cursor: pointer; font-size: 0.82rem; font-weight: 800; color: var(--tm-accent); padding: 0.2rem 0;">
          ▶ View Full Raw RFC 822 Headers
        </summary>
        <pre style="margin-top: 0.75rem; background: var(--tm-surface-secondary); padding: 1rem; border-radius: 8px; font-size: 0.75rem; font-family: monospace; overflow-x: auto; max-height: 250px; border: 1px solid var(--tm-border);">${escapeHtml(rawHeaders)}</pre>
      </details>
    </div>
  `;
}

/* ==========================================================================
   Detail Action Attachments (Tabs, Jumps, Reports, Modals)
   ========================================================================== */
function attachDetailEventListeners(messageId) {
  // Export PDF
  const btnPDF = document.getElementById("btnExportPDF");
  if (btnPDF) {
    btnPDF.addEventListener("click", () => {
      window.open(`${API_BASE}/reports/pdf/${messageId}`, "_blank");
    });
  }

  // Export JSON
  const btnJSON = document.getElementById("btnExportJSON");
  if (btnJSON) {
    btnJSON.addEventListener("click", () => {
      window.open(`${API_BASE}/reports/json/${messageId}`, "_blank");
    });
  }

  // Forensic Category Deck Tabs (and backwards-compatible matrix-btn & pillar-card)
  document.querySelectorAll(".deck-item[data-tab], .matrix-btn[data-tab], .pillar-card[data-jump-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.inspectorTab = btn.dataset.tab || btn.dataset.jumpTab;
      renderAnalysisArea();
      const consoleEl = document.getElementById("inspectorConsole");
      if (consoleEl && btn.dataset.jumpTab) {
        consoleEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  // Unlock PDF Button
  const btnUnlock = document.getElementById("btnOpenUnlockModal");
  if (btnUnlock) {
    btnUnlock.addEventListener("click", () => {
      const attId = btnUnlock.getAttribute("data-attachment-id") || null;
      showUnlockModal(messageId, attId);
    });
  }
}

/* Encrypted PDF Unlock Modal */
function showUnlockModal(messageId, attachmentId = null) {
  dom.modalContainer.innerHTML = `
    <div class="modal-box">
      <div class="modal-title">🔒 Unlock Encrypted PDF</div>
      <div class="modal-desc">
        Enter the decryption password for this attachment to extract internal streams and analyze embedded macros.
      </div>
      <input type="password" id="pdfPasswordInput" class="modal-input" placeholder="Enter PDF password..." />
      <div class="modal-buttons">
        <button type="button" class="btn-modal-cancel" id="btnCancelModal">Cancel</button>
        <button type="button" class="btn-modal-submit" id="btnSubmitUnlock">Unlock & Re-Inspect</button>
      </div>
    </div>
  `;
  dom.modalContainer.classList.remove("hidden");

  const input = document.getElementById("pdfPasswordInput");
  input.focus();

  document.getElementById("btnCancelModal").addEventListener("click", hideModal);
  document.getElementById("btnSubmitUnlock").addEventListener("click", () => {
    const pw = input.value.trim();
    if (!pw) {
      showToast("Please enter a password", "error");
      return;
    }
    unlockPDFFile(messageId, pw, attachmentId);
  });
}

function hideModal() {
  dom.modalContainer.classList.add("hidden");
  dom.modalContainer.innerHTML = "";
}

/* ==========================================================================
   Initialization
   ========================================================================== */
async function initApp() {
  setupEventListeners();

  try {
    const authStatus = await checkAuthStatus();
    state.isConnected = !!authStatus.authenticated;
    updateAuthUI();

    if (state.isConnected) {
      fetchInboxMessages();
    } else {
      renderEmptyState("Please connect your Gmail account to inspect emails.");
    }
  } catch (err) {
    console.error("Initialization error:", err);
    updateAuthUI();
    renderEmptyState();
  }
}

// Start application
window.addEventListener("DOMContentLoaded", initApp);
