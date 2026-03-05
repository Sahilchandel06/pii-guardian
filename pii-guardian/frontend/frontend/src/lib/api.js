const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export async function apiRequest(path, { token, method = "GET", body, headers = {} } = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body,
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = payload.detail;
    if (Array.isArray(detail)) {
      throw new Error(detail.map((item) => `${item.loc?.join(".") || "field"}: ${item.msg}`).join(" | "));
    }
    throw new Error(detail || "Request failed");
  }

  return response;
}

export { API_BASE };
