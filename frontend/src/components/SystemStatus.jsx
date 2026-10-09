import { useEffect, useState } from "react";
import { Check, X } from "lucide-react";
import { getHealth } from "../services/api";

export default function SystemStatus() {
  const [h, setH] = useState(null); // null = backend unreachable
  const [checking, setChecking] = useState(true);
  useEffect(() => {
    let active = true;
    let timer;
    let retryDelay = 1000;

    const check = async () => {
      let connected = false;
      try {
        const health = await getHealth();
        if (health?.status !== "ok") throw new Error("Backend health check failed");
        connected = true;
        retryDelay = 1000;
        if (active) setH(health);
      } catch {
        if (active) setH(null);
      } finally {
        if (active) setChecking(false);
      }

      if (!active) return;
      timer = window.setTimeout(check, connected ? 10000 : retryDelay);
      if (!connected) retryDelay = Math.min(retryDelay * 2, 10000);
    };

    check();
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, []);
  const online = h?.status === "ok";
  const statusText = checking
    ? "Checking Guardrail Engine..."
    : online ? "Guardrail Engine Online" : "Guardrail Engine Offline";
  const statusColor = checking
    ? "bg-amber-400"
    : online ? "bg-emerald-400" : "bg-rose-500";
  const items = [
    ["Backend connected", online],
    [online ? `Policies loaded (${h.policies})` : "Policies loaded", online && h.policies > 0],
    ["Validation ready", online && h.validation],
  ];
  return (
    <div className="text-xs">
      <div className="flex items-center gap-2 text-sm font-medium">
        <span className={`h-2.5 w-2.5 rounded-full ${statusColor}`} />
        {statusText}
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
