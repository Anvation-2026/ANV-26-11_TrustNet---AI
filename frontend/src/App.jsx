import { useState } from "react";
import Home from "./pages/Home";
import Simulator from "./pages/Simulator";
import Dashboard from "./pages/Dashboard";
import SystemStatus from "./components/SystemStatus";

const PAGES = { Home, Simulator, Dashboard };

export default function App() {
  const [page, setPage] = useState("Home");
  const Page = PAGES[page];
  return (
    <div className="min-h-screen bg-stone-100 text-stone-800">
      <header className="bg-stone-900 text-stone-100">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
          <span className="font-semibold">TrustNet AI</span>
          <nav className="flex gap-6">
            {Object.keys(PAGES).map((p) => (
              <button key={p} onClick={() => setPage(p)}
                className={`text-sm ${page === p ? "text-white underline underline-offset-8" : "text-stone-400 hover:text-white"}`}>
                {p}
              </button>
            ))}
          </nav>
          <div className="ml-auto"><SystemStatus /></div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-8"><Page go={setPage} /></main>
    </div>
  );
}
