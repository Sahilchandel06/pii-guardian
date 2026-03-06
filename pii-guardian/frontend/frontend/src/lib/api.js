const inferApiBase = () => {
  if (typeof window === "undefined") return "http://127.0.0.1:8000";
  return `${window.location.protocol}//${window.location.hostname}:8000`;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || inferApiBase();

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
