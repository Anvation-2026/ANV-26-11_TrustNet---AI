import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { Activity, CheckCircle2, XCircle, AlertTriangle, Gauge, RefreshCw } from "lucide-react";
import { getStats, getLogs } from "../services/api";
import StatCard from "../components/StatCard";
import { DecisionBadge } from "../components/DecisionCard";

const DECISION_COLORS = { Allow: "#10b981", Warn: "#eab308", Block: "#ef4444" };
const RISK_COLORS = { "Unauthorized Action": "#e11d48", "Invalid Parameter": "#f59e0b",
  "Redundant Call": "#0ea5e9", "Policy Violation": "#7c3aed", "Adaptive Behavior": "#6366f1", Low: "#10b981", Medium: "#eab308", High: "#ef4444" };
const barTone = (n) => (n >= 80 ? "bg-emerald-500" : n >= 50 ? "bg-amber-500" : "bg-rose-500");
const card = "rounded-lg bg-white p-5 shadow-sm";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    try { setStats(await getStats()); setLogs(await getLogs()); setError(""); }
    catch { setError("Could not load data. Check that the backend is running on port 8000."); }
  }
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  if (error) return <p className="text-rose-700">{error}</p>;
  if (!stats) return <p className="text-stone-500">Loading...</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-stone-900">Dashboard</h1>
        <button onClick={load} className="flex items-center gap-1 rounded border border-stone-300 px-3 py-1 text-sm hover:bg-white">
          <RefreshCw size={14} />Refresh
        </button>
      </div>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total requests" value={stats.total} tone="blue" Icon={Activity} />
        <StatCard label="Allowed" value={stats.allowed} tone="green" Icon={CheckCircle2} />
        <StatCard label="Blocked" value={stats.blocked} tone="red" Icon={XCircle} />
        <StatCard label="Warnings" value={stats.warned} tone="yellow" Icon={AlertTriangle} />
      </div>
      <div className={card}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-medium"><Gauge size={18} />Average reliability score</div>
          <span className="text-2xl font-semibold">{stats.reliability}%</span>
        </div>
        <div className="mt-3 h-2.5 rounded bg-stone-200">
          <div className={`h-2.5 rounded ${barTone(stats.reliability)}`} style={{ width: `${stats.reliability}%` }} />
        </div>
      </div>
      <div className="grid gap-6 md:grid-cols-3">
        <div className={`${card} md:col-span-1`}>
          <h2 className="mb-2 font-medium">Decisions</h2>
          {stats.total === 0 ? (
            <p className="text-sm text-stone-500">No requests yet. Run one in the Simulator.</p>
          ) : (
            <div className="h-64">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={stats.decisions} dataKey="value" nameKey="name" outerRadius={80}>
                    {stats.decisions.map((d) => <Cell key={d.name} fill={DECISION_COLORS[d.name]} />)}
                  </Pie>
                  <Tooltip />
                  <Legend formatter={(v) => `${v.toUpperCase()} (${stats.decisions.find((d) => d.name === v)?.value ?? 0})`} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
          <h3 className="mt-4 text-sm font-medium text-stone-600">By risk type</h3>
          <ul className="mt-1 space-y-1 text-sm">
            {stats.risk_types.map((r) => (
              <li key={r.name} className="flex justify-between">
                <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full" style={{ background: RISK_COLORS[r.name] }} />{r.name}</span>
                <span>{r.value}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className={`${card} overflow-x-auto md:col-span-2`}>
          <h2 className="mb-2 font-medium">Request history</h2>
          <table className="w-full text-left text-sm">
            <thead className="text-stone-500">
              <tr><th className="py-1 pr-3">Timestamp</th><th className="pr-3">Role</th><th className="pr-3">Tool</th>
                <th className="pr-3">Decision</th><th className="pr-3">Rule triggered</th><th>Reliability score</th></tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id} className="border-t border-stone-100">
                  <td className="whitespace-nowrap py-1.5 pr-3">{new Date(l.ts * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "medium" })}</td>
                  <td className="pr-3">{l.role}</td><td className="pr-3">{l.tool}</td>
                  <td className="pr-3"><DecisionBadge decision={l.decision} /></td>
                  <td className="pr-3">{l.rule === "-" ? "None" : l.rule}</td><td>{l.reliability}%</td>
                </tr>
              ))}
              {logs.length === 0 && <tr><td colSpan={6} className="py-3 text-stone-500">No requests yet. Run one in the Simulator.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
