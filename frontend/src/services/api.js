const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function req(path, opts) {
  const res = await fetch(BASE + path, opts);
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res.json();
}

export const evaluate = (body) =>
  req("/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
export const getStats = () => req("/stats");
export const getLogs = () => req("/logs");
export const getHealth = () => req("/health");
