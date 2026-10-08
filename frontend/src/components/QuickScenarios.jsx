import { Zap } from "lucide-react";
import { SCENARIOS } from "../services/scenarios";

const TONE = {
  good: "border-emerald-300 bg-emerald-50 text-emerald-800 hover:bg-emerald-100",
  bad: "border-rose-300 bg-rose-50 text-rose-800 hover:bg-rose-100",
  warn: "border-yellow-300 bg-yellow-50 text-yellow-800 hover:bg-yellow-100",
};

export default function QuickScenarios({ onSelect, loaded }) {
  return (
    <section className="rounded-lg bg-white p-6 shadow-sm">
      <h2 className="flex items-center gap-2 text-xl font-semibold text-stone-900"><Zap size={20} />Quick Demo Scenarios</h2>
      <p className="mt-1 text-sm text-stone-600">Load a ready-made request into the manual simulator, then click Run Guardrail Check.</p>
      <div className="mt-4 flex flex-wrap gap-2">
        {SCENARIOS.map((s) => (
          <button key={s.label} onClick={() => onSelect(s)}
            className={`rounded border px-3 py-2 text-sm font-medium ${TONE[s.tone]} ${loaded?.label === s.label ? "ring-2 ring-stone-900" : ""}`}>
            {s.icon} {s.label}
          </button>
        ))}
      </div>
    </section>
  );
}
