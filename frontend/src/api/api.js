const API_BASE = "http://localhost:8000";

export async function getMessages(options = {}) {
  const { signal, limit = 10, period = "recent", pageToken, sender, subject, keyword, domain, after, before } = options;

  const params = new URLSearchParams();
  params.set("limit", String(limit));
  params.set("period", period);
  if (pageToken)  params.set("page_token", pageToken);
  if (sender)     params.set("sender", sender);
  if (subject)    params.set("subject", subject);
  if (keyword)    params.set("keyword", keyword);
  if (domain)     params.set("domain", domain);
  if (after)      params.set("after", after);
  if (before)     params.set("before", before);

  const response = await fetch(`${API_BASE}/gmail/messages?${params.toString()}`, {
    credentials: "include",
    signal,
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error("UNAUTHORIZED");
    throw new Error(`Failed to fetch messages: ${response.status}`);
  }

  return response.json();
}

export async function getMessage(id, options = {}) {
  const response = await fetch(`${API_BASE}/gmail/message/${id}`, {
    credentials: "include",
    signal: options.signal
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error("UNAUTHORIZED");
    throw new Error(`Failed to fetch message: ${response.status}`);
  }

  return response.json();
}

export async function logout(options = {}) {
  const response = await fetch(`${API_BASE}/auth/logout`, {
    method: "POST",
    credentials: "include",
    signal: options.signal
  });

  if (!response.ok) {
    throw new Error(`Failed to logout: ${response.status}`);
  }

  return response.json();
}

export async function checkSessionStatus(options = {}) {
  const response = await fetch(`${API_BASE}/auth/status`, {
    credentials: "include",
    signal: options.signal
  });
  
  if (!response.ok) {
    return { authenticated: false };
  }
  
  return response.json();
}
