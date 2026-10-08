import { useRef, useState } from "react";
import { evaluate } from "../services/api";
import DecisionCard from "../components/DecisionCard";
import AgentOutput from "../components/AgentOutput";
import QuickScenarios from "../components/QuickScenarios";

const TOOLS = ["read_file", "delete_user", "export_data", "send_email", "process_payment", "schedule_event"];
const EXAMPLES = {
  read_file: { role: "Viewer", params: { path: "/documents/company_policy.pdf" } },
  delete_user: { role: "Viewer", params: { user_id: 1024, reason: "Inactive account" } },
  export_data: { role: "Teacher", params: { dataset: "customer_records", format: "csv" } },
  send_email: { role: "Teacher", params: { to: "manager@company.com", subject: "Monthly Sales Report", body: "Please find the report attached." } },
  process_payment: { role: "Admin", params: { recipient: "ABC Suppliers", amount: 50000, currency: "INR" } },
  schedule_event: { role: "Teacher", params: { title: "Project Review Meeting", date: "2026-10-15", time: "10:00", attendees: ["lead@company.com", "team@company.com"] } },
};
const pretty = (tool) => JSON.stringify(EXAMPLES[tool].params, null, 2);
const field = "mt-1 w-full rounded border border-stone-300 bg-white px-3 py-2";
const makeTraceId = () => `demo-${crypto.randomUUID()}`;

export default function Simulator() {
  const [traceId, setTraceId] = useState(() => {
    const saved = sessionStorage.getItem("pygenic-demo-trace-id");
    if (saved) return saved;
    const fresh = makeTraceId();
    sessionStorage.setItem("pygenic-demo-trace-id", fresh);
    return fresh;
  });
  const [form, setForm] = useState({
    role: EXAMPLES.read_file.role, tool: "read_file", action: "Execute", params: pretty("read_file"),
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const loadExample = (tool, role = form.role) => {
    setForm({ ...form, role, tool, action: "Execute", params: pretty(tool) });
    setResult(null); setError("");
  };

  const populate = (req) => {
    setForm({ role: req.role, tool: req.tool, action: req.action, params: JSON.stringify(req.params, null, 2) });
    setResult(null); setError("");
  };

  const manualRef = useRef(null);
  const [loaded, setLoaded] = useState(null);
  const resetTrace = () => {
    const fresh = makeTraceId();
    sessionStorage.setItem("pygenic-demo-trace-id", fresh);
    setTraceId(fresh); setResult(null); setLoaded(null); setError("");
  };
  const loadScenario = (s) => {
    setForm({ role: s.role, tool: s.tool, action: s.action, params: JSON.stringify(s.params, null, 2) });
    setResult(null); setError(""); setLoaded(s);
    manualRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  async function submit(e) {
    e.preventDefault();
    setError("");
    let params;
    try { params = JSON.parse(form.params || "{}"); } catch { return setError("Parameters must be valid JSON."); }
    setBusy(true);
    try { setResult(await evaluate({ ...form, params, trace_id: traceId })); }
    catch { setError("Could not evaluate the request. Check that the backend is running on port 8000 and that parameters are a JSON object."); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-8">
      <QuickScenarios onSelect={loadScenario} loaded={loaded} />
      <AgentOutput onPopulate={populate} />
      <section ref={manualRef} className="scroll-mt-4 rounded-lg bg-white p-6 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><h2 className="mb-1 text-xl font-semibold text-stone-900">Manual simulator</h2>
            <p className="text-xs text-stone-500">Adaptive demo trace: {traceId.slice(0, 18)} · history is isolated to this browser session.</p></div>
          <button type="button" onClick={resetTrace} className="rounded border border-stone-300 px-3 py-1.5 text-sm hover:bg-stone-50">Reset adaptive demo</button>
        </div>
        {loaded && <p className="mb-4 text-sm text-stone-600">Loaded "{loaded.label}". {loaded.hint} Click Run Guardrail Check to execute.</p>}
        <div className="mb-4" />
    <div className="grid gap-8 md:grid-cols-2">
      <form onSubmit={submit} className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-stone-500">Load example:</span>
          {TOOLS.map((t) => (
            <button type="button" key={t} onClick={() => loadExample(t, EXAMPLES[t].role)}
              className="rounded border border-stone-300 px-2 py-1 hover:bg-white">{t}</button>
          ))}
        </div>
        <label className="block text-sm">User role
          <select className={field} value={form.role} onChange={set("role")}>
            {["Admin", "Teacher", "Viewer"].map((r) => <option key={r}>{r}</option>)}
          </select>
        </label>
        <label className="block text-sm">Tool
          <select className={field} value={form.tool} onChange={(e) => loadExample(e.target.value)}>
            {[...new Set([...TOOLS, form.tool])].map((t) => <option key={t}>{t}</option>)}
          </select>
        </label>
        <label className="block text-sm">Action
          <select className={field} value={form.action} onChange={set("action")}>
            {[...new Set(["Execute", "Read", form.action])].map((a) => <option key={a}>{a}</option>)}
          </select>
        </label>
        <label className="block text-sm">Parameters (JSON)
          <textarea rows={6} className={`${field} font-mono text-sm`} value={form.params} onChange={set("params")} />
        </label>
        {error && <p className="text-sm text-rose-700">{error}</p>}
        <button disabled={busy} className="rounded bg-stone-900 px-4 py-2 text-white hover:bg-stone-700 disabled:opacity-50">
          {busy ? "Checking..." : "Run Guardrail Check"}
        </button>
      </form>
      <div>
        {result ? <DecisionCard r={result} /> : (
          <p className="text-stone-500">Submit a request to see the decision, rule and reliability score.</p>
        )}
      </div>
    </div>
      </section>
    </div>
  );
}
