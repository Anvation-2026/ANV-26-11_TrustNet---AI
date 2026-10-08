const STYLE = {
  Allow: { emoji: "🟢", bar: "bg-emerald-500", badge: "bg-emerald-100 text-emerald-800", ring: "border-emerald-300", text: "text-emerald-700" },
  Warn: { emoji: "🟡", bar: "bg-yellow-500", badge: "bg-yellow-100 text-yellow-800", ring: "border-yellow-300", text: "text-yellow-700" },
  Block: { emoji: "🔴", bar: "bg-red-500", badge: "bg-red-100 text-red-800", ring: "border-red-300", text: "text-red-700" },
};

export function DecisionBadge({ decision }) {
  const s = STYLE[decision];
  return <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold ${s.badge}`}>{s.emoji} {decision.toUpperCase()}</span>;
}

export default function DecisionCard({ r }) {
  const s = STYLE[r.decision];
  return (
    <div className={`rounded-lg border-2 bg-white p-5 ${s.ring}`}>
      <h3 className={`text-lg font-semibold ${s.text}`}>{s.emoji} Decision: {r.decision.toUpperCase()}</h3>
      <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
        <div><dt className="text-stone-500">Risk type</dt><dd className="font-medium">{r.risk_type}</dd></div>
        <div><dt className="text-stone-500">Violated rule</dt><dd className="font-medium">{r.rule === "-" ? "None" : r.rule}</dd></div>
        <div><dt className="text-stone-500">Reliability score</dt><dd className="font-medium">{r.reliability}%</dd></div>
      </dl>
      <div className="mt-3 h-2 rounded bg-stone-200"><div className={`h-2 rounded ${s.bar}`} style={{ width: `${r.reliability}%` }} /></div>
      <div className="mt-4 rounded bg-stone-50 p-3">
        <div className="text-sm text-stone-500">Explanation</div>
        <p className="mt-1 text-stone-900">{r.explanation}</p>
      </div>
    </div>
  );
}
