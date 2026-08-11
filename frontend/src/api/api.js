const API_BASE = "http://localhost:8000";

export async function getMessages() {
  const response = await fetch(`${API_BASE}/gmail/messages`, {
    credentials: "include"
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error("UNAUTHORIZED");
    throw new Error(`Failed to fetch messages: ${response.status}`);
  }

  return response.json();
}

export async function getMessage(id) {
  const response = await fetch(`${API_BASE}/gmail/message/${id}`, {
    credentials: "include"
  });

  if (!response.ok) {
    if (response.status === 401) throw new Error("UNAUTHORIZED");
    throw new Error(`Failed to fetch message: ${response.status}`);
  }

  return response.json();
}

export async function logout() {
  const response = await fetch(`${API_BASE}/auth/logout`, {
    method: "POST",
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error(`Failed to logout: ${response.status}`);
  }

  return response.json();
}

export async function checkSessionStatus() {
  const response = await fetch(`${API_BASE}/auth/status`, {
    credentials: "include"
  });
  
  if (!response.ok) {
    return { authenticated: false };
  }
  
  return response.json();
}
