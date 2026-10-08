export default function Home({ go }) {
  return (
    <section className="max-w-2xl">
      <h1 className="text-4xl font-semibold text-stone-900">Stop unsafe agent actions before they run.</h1>
      <p className="mt-4 text-lg text-stone-600">
        TrustNet-AI checks every AI-agent request for unauthorized actions, invalid parameters,
        redundant calls and policy violations, then returns Allow, Warn or Block with a reason and a reliability score.
      </p>
      <div className="mt-8 flex gap-3">
        <button onClick={() => go("Simulator")} className="rounded bg-stone-900 px-4 py-2 text-white hover:bg-stone-700">
          Try the simulator
        </button>
        <button onClick={() => go("Dashboard")} className="rounded border border-stone-300 px-4 py-2 hover:bg-white">
          View dashboard
        </button>
      </div>
    </section>
  );
}
