const API_BASE = "http://localhost:8000";

export async function getMessages(options = {}) {
  const { signal, limit = 10, period = "recent", pageToken, sender, subject, keyword, domain, after, before } = options;

  const params = new URLSearchParams();
  params.set("limit", String(limit));
  params.set("period", period);
  if (pageToken) params.set("page_token", pageToken);
  if (sender) params.set("sender", sender);
  if (subject) params.set("subject", subject);
  if (keyword) params.set("keyword", keyword);
  if (domain) params.set("domain", domain);
  if (after) params.set("after", after);
  if (before) params.set("before", before);

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

export async function streamMessage(id, {
  signal,
  onProgress,
  onResult,
  onError,
} = {}) {
  const url = `${API_BASE}/gmail/message/${id}/stream`;

  console.log("STREAM DEBUG 1 - function entered");
  console.log("STREAM DEBUG 2 - API_BASE:", API_BASE);
  console.log("STREAM DEBUG 3 - URL:", url);
  console.log("STREAM DEBUG 4 - signal aborted:", signal?.aborted);

  let response;

  try {
    console.log("STREAM DEBUG 5 - about to call fetch");

    response = await fetch(url, {
      method: "GET",
      credentials: "include",
      signal,
      cache: "no-store",
      headers: {
        Accept: "text/event-stream",
      },
    });

    console.log("STREAM DEBUG 6 - fetch returned");
    console.log("STREAM DEBUG 7 - status:", response.status);
    console.log("STREAM DEBUG 8 - ok:", response.ok);
    console.log("STREAM DEBUG 9 - content-type:", response.headers.get("content-type"));

  } catch (error) {
    console.error("STREAM DEBUG FETCH ERROR:", error);
    console.error("STREAM DEBUG error name:", error?.name);
    console.error("STREAM DEBUG error message:", error?.message);
    throw error;
  }

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("UNAUTHORIZED");
    }

    throw new Error(`Failed to stream message: ${response.status}`);
  }

  if (!response.body) {
    throw new Error("Streaming is not supported by this browser.");
  }

  console.log("STREAM DEBUG 10 - response body exists");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";

  try {
    while (true) {
      console.log("STREAM DEBUG 11 - waiting for stream chunk");

      const { value, done } = await reader.read();

      console.log("STREAM DEBUG 12 - reader result:", {
        done,
        bytes: value?.length ?? 0,
      });

      if (done) {
        console.log("STREAM DEBUG 13 - stream completed");
        break;
      }

      buffer += decoder.decode(value, { stream: true });

      const events = buffer.split("\n\n");
      buffer = events.pop() || "";

      for (const eventText of events) {
        console.log("STREAM DEBUG 14 - SSE event:", eventText);

        const dataLine = eventText
          .split("\n")
          .find((line) => line.startsWith("data:"));

        if (!dataLine) {
          continue;
        }

        const payload = dataLine.slice(5).trim();

        if (!payload) {
          continue;
        }

        let event;

        try {
          event = JSON.parse(payload);
        } catch (parseError) {
          console.warn("Invalid SSE payload:", payload, parseError);
          continue;
        }

        console.log("STREAM DEBUG 15 - parsed event:", event);

        if (event.type === "progress") {
          onProgress?.(event);
        } else if (event.type === "result") {
          onResult?.(event.data);
        } else if (event.type === "error") {
          onError?.(event);
        }
      }
    }
  } finally {
    console.log("STREAM DEBUG 16 - releasing reader");
    reader.releaseLock();
  }
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
