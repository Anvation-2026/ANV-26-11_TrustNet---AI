import { useEffect, useState } from "react";
import { Check, X } from "lucide-react";
import { getHealth } from "../services/api";

export default function SystemStatus() {
  const [h, setH] = useState(null); // null = backend unreachable
  useEffect(() => {
    const load = () => getHealth().then(setH).catch(() => setH(null));
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);
  const online = !!h;
  const items = [
    ["Backend connected", online],
    [online ? `Policies loaded (${h.policies})` : "Policies loaded", online && h.policies > 0],
    ["Validation ready", online && h.validation],
  ];
  return (
    <div className="text-xs">
      <div className="flex items-center gap-2 text-sm font-medium">
        <span className={`h-2.5 w-2.5 rounded-full ${online ? "bg-emerald-400" : "bg-rose-500"}`} />
        {online ? "Guardrail Engine Online" : "Guardrail Engine Offline"}
      </div>
      <ul className="mt-1 flex flex-wrap gap-x-3 text-stone-400">
        {items.map(([text, ok]) => (
          <li key={text} className="flex items-center gap-1">
            {ok ? <Check size={12} className="text-emerald-400" /> : <X size={12} className="text-rose-400" />}{text}
          </li>
        ))}
      </ul>
    </div>
  );
}
