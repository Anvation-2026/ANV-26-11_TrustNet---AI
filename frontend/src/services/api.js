const BASE = (import.meta.env.VITE_API_URL || "/api").replace(/\/$/, "");

async function req(path, opts) {
  let res;
  try {
    res = await fetch(BASE + path, opts);
  } catch {
    throw new Error(
      `Cannot reach the API at ${BASE}. Start the app with "npm run dev" from the frontend folder; this also starts the backend. Check the terminal for backend startup errors.`,
    );
  }
  if (!res.ok) {
    let message = "";
    try {
      const payload = await res.json();
      message = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail ?? payload);
    } catch {
      message = await res.text().catch(() => "");
    }
    throw new Error(message || `Request failed (${res.status})`);
  }
  return res.json();
}

export const evaluate = (body) =>
  req("/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
export const getStats = () => req("/stats");
export const getLogs = () => req("/logs");
export const getHealth = () => req("/health");
export const verifyEmail = (email) => req("/email/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) });
export const verifyPersonalEmail = (email) => req("/email/verify-personal", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) });
export const analyzeEmail = (body) => req("/email/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
export const getEmailHistory = (q = "") => req(`/email/history?q=${encodeURIComponent(q)}`);
export const getEmailStats = () => req("/email/stats");
