import { useEffect, useState } from "react";
import { analyzeEmail, getEmailHistory, getEmailStats, verifyEmail, verifyPersonalEmail } from "../services/api";
import { DecisionBadge } from "../components/DecisionCard";

const card = "rounded-xl border border-stone-200 bg-white p-5 shadow-sm dark:border-stone-700 dark:bg-stone-900";
const input = "mt-1 w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm text-stone-900 outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 dark:border-stone-600 dark:bg-stone-800 dark:text-stone-100";

function Result({ result }) {
  if (!result) return null;
  return <section className={`${card} mt-5`}>
    <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-lg font-semibold">Trust assessment</h3><DecisionBadge decision={result.decision} /></div>
    <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
      {[ ["Trust Score", `${result.trust_score}/100`], ["Risk", result.risk], ["Confidence", `${result.confidence}%`], ["Decision", result.decision.toUpperCase()] ].map(([label, value]) => <div key={label} className="rounded-lg bg-stone-50 p-3 dark:bg-stone-800"><div className="text-xs text-stone-500">{label}</div><div className="mt-1 font-semibold">{value}</div></div>)}
    </div>
    {typeof result.personal_address === "boolean" && <p className="mt-3 text-sm"><b>Personal provider:</b> {result.personal_address ? "Recognized free-mail provider" : "Not identified as a common free-mail provider"}</p>}
    {result.checks_passed && <div className="mt-4 text-sm"><b>Checks passed:</b> {result.checks_passed.join(", ") || "None"}<br/><b>Checks failed:</b> {result.checks_failed.join(", ") || "None"}</div>}
    {result.checks_unavailable?.length > 0 && <p className="mt-2 text-sm text-amber-700 dark:text-amber-300"><b>Checks unavailable:</b> {result.checks_unavailable.join(", ")}</p>}
    {result.checks && <ul className="mt-3 space-y-1 text-sm">{result.checks.map((check) => <li key={check.name} className="flex flex-wrap gap-x-2"><b>{check.name}:</b><span className={check.status === "pass" ? "text-emerald-700 dark:text-emerald-300" : check.status === "fail" ? "text-rose-700 dark:text-rose-300" : "text-amber-700 dark:text-amber-300"}>{check.status}</span><span className="text-stone-600 dark:text-stone-300">{check.detail}</span></li>)}</ul>}
    {result.auth_checks?.length > 0 && <div className="mt-4 rounded-lg border border-stone-200 p-3 text-sm dark:border-stone-700"><b>Incoming message authentication headers</b><ul className="mt-2 space-y-1">{result.auth_checks.map((check, i) => <li key={`${check.mechanism}-${i}`}>{check.mechanism}: <span className={check.status === "pass" ? "text-emerald-700 dark:text-emerald-300" : ["fail", "softfail", "permerror", "mismatch"].includes(check.status) ? "text-rose-700 dark:text-rose-300" : "text-amber-700 dark:text-amber-300"}>{check.status}</span> <span className="text-stone-500">({check.source})</span></li>)}</ul><p className="mt-2 text-xs text-stone-500">{result.auth_header_notice}</p></div>}
    {result.threat_intelligence_check && <div className="mt-4 rounded-lg border border-stone-200 p-3 text-sm dark:border-stone-700">
      <b>Live URL threat intelligence</b>
      <p className="mt-1 text-stone-600 dark:text-stone-300">Provider: {result.threat_intelligence_check.provider} · Status: {result.threat_intelligence_check.status}{result.threat_intelligence_check.checked_at ? ` · Feed refreshed ${new Date(result.threat_intelligence_check.checked_at).toLocaleString()}` : ""}{Number.isFinite(result.threat_intelligence_check.feed_entries) ? ` · ${result.threat_intelligence_check.feed_entries.toLocaleString()} feed entries` : ""}</p>
      {result.threat_intelligence?.length > 0 && <ul className="mt-2 space-y-1">{result.threat_intelligence.map(item=><li key={item.url} className="break-all"><span className={item.status === "match" ? "font-medium text-rose-700 dark:text-rose-300" : item.status === "no_match" ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300"}>{item.status.replaceAll("_", " ")}</span> · {item.url}{item.threat_types?.length > 0 ? ` (${item.threat_types.join(", ")})` : ""}{item.virustotal_status && item.virustotal_status !== "not_configured" ? ` · VirusTotal: ${item.virustotal_status}${item.virustotal_malicious || item.virustotal_suspicious ? ` (${item.virustotal_malicious} malicious, ${item.virustotal_suspicious} suspicious)` : ""}` : ""}</li>)}</ul>}
      <p className="mt-2 text-xs text-stone-500">{result.threat_intelligence_check.note} A no-match result is not proof a URL is safe.</p>
    </div>}
    {result.findings && <div className="mt-4 text-sm"><b>Signals:</b> {result.findings.join(", ") || "None detected"}<br/><b>URLs:</b> {result.urls.length ? result.urls.join(", ") : "None found"}<br/><b>Domains:</b> {result.domains.length ? result.domains.join(", ") : "None found"}</div>}
    <div className="mt-4"><b className="text-sm">Reasons</b><ul className="mt-1 list-inside list-disc text-sm text-stone-600 dark:text-stone-300">{result.reasons.map((reason, i) => <li key={i}>{reason}</li>)}</ul></div>
    <p className="mt-3 rounded-lg bg-indigo-50 p-3 text-sm text-indigo-950 dark:bg-indigo-950 dark:text-indigo-100"><b>Recommendation:</b> {result.recommendation}</p>
    <p className="mt-2 text-xs text-stone-500">{result.notice || "Technical trust signals only. This assessment does not verify mailbox ownership or identify a person."}</p>
  </section>;
}

export default function EmailTrust() {
  const [tab, setTab] = useState("Address Verification");
  const [email, setEmail] = useState("");
  const [personalEmail, setPersonalEmail] = useState("");
  const [personalResult, setPersonalResult] = useState(null);
  const [personalBusy, setPersonalBusy] = useState(false);
  const [personalError, setPersonalError] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [rawHeaders, setRawHeaders] = useState("");
  const [checkUrls, setCheckUrls] = useState(false);
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState({ scanned: 0, safe: 0, suspicious: 0, high_risk: 0 });
  const [history, setHistory] = useState([]);
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh(query = search) {
    try { const [s, h] = await Promise.all([getEmailStats(), getEmailHistory(query)]); setStats(s); setHistory(h); }
    catch { setError("Email Trust service is unavailable. Check that the backend is running."); }
  }
  useEffect(() => { refresh(""); }, []);
  useEffect(() => { const timer = setTimeout(() => refresh(search), 250); return () => clearTimeout(timer); }, [search]);

  async function submit(event) {
    event.preventDefault(); setBusy(true); setError(""); setResult(null);
    try {
      const value = tab === "Address Verification" ? await verifyEmail(email) : await analyzeEmail({ sender_email: sender, subject, body, raw_headers: rawHeaders, check_urls: checkUrls });
      setResult(value); await refresh();
    } catch (e) { setError(e.message || "Analysis failed. Please try again."); }
    finally { setBusy(false); }
  }
  async function submitPersonal(event) {
    event.preventDefault(); setPersonalBusy(true); setPersonalError(""); setPersonalResult(null);
    try {
      setPersonalResult(await verifyPersonalEmail(personalEmail));
      await refresh();
    } catch (e) { setPersonalError(e.message || "Personal email check failed. Please try again."); }
    finally { setPersonalBusy(false); }
  }
  function exportHistory() {
    const rows = [["Timestamp", "Scan Type", "Decision", "Trust Score", "Risk", "Confidence", "Summary"], ...history.map(x => [new Date(x.ts * 1000).toISOString(), x.scan_type, x.decision, x.reliability, x.risk_type, x.confidence, x.explanation])];
    const csv = rows.map(row => row.map(value => {
      let cell = String(value ?? "");
      if (/^\s*[=+@-]/.test(cell)) cell = `'${cell}`;
      return `"${cell.replaceAll('"', '""')}"`;
    }).join(",")).join("\n");
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); link.download = "email-trust-history.csv"; link.click(); URL.revokeObjectURL(link.href);
  }

  return <div className="space-y-6 text-stone-900 dark:text-stone-100">
    <div><p className="text-sm font-medium text-indigo-600">TRUSTNET-AI / TRUST CENTER</p><h1 className="mt-1 text-3xl font-semibold">Email Trust</h1><p className="mt-1 text-sm text-stone-500">Assess technical sender signals and message risk before taking action.</p></div>
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[["Emails Scanned",stats.scanned,"text-stone-900"],["Safe Emails",stats.safe,"text-emerald-600"],["Suspicious Emails",stats.suspicious,"text-amber-600"],["High Risk Emails",stats.high_risk,"text-rose-600"]].map(([name,value,tone])=><div key={name} className={card}><div className="text-sm text-stone-500">{name}</div><div className={`mt-2 text-3xl font-semibold ${tone}`}>{value}</div></div>)}</div>
    <section className={card}>
      <div className="flex flex-wrap gap-2 border-b border-stone-200 pb-4 dark:border-stone-700">{["Address Verification","Content Analysis"].map(name=><button key={name} onClick={()=>{setTab(name);setResult(null);}} className={`rounded-lg px-4 py-2 text-sm font-medium ${tab===name?"bg-stone-900 text-white dark:bg-indigo-600":"text-stone-600 hover:bg-stone-100 dark:text-stone-300 dark:hover:bg-stone-800"}`}>{name}</button>)}</div>
      <form onSubmit={submit} className="mt-5 space-y-4">
        {tab === "Address Verification" ? <label className="block text-sm font-medium">Email Address<input required type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="security@company.com" className={input}/></label> : <>
          <label className="block text-sm font-medium">Sender Email<input required type="email" value={sender} onChange={e=>setSender(e.target.value)} placeholder="sender@company.com" className={input}/></label>
          <label className="block text-sm font-medium">Subject<input value={subject} onChange={e=>setSubject(e.target.value)} placeholder="Message subject" className={input}/></label>
          <label className="block text-sm font-medium">Email Body<textarea required rows={6} value={body} onChange={e=>setBody(e.target.value)} placeholder="Paste the message body here" className={input}/></label>
          <label className="block text-sm font-medium">Original Authentication Headers (optional)<textarea rows={4} value={rawHeaders} onChange={e=>setRawHeaders(e.target.value)} placeholder="Paste Authentication-Results and Received-SPF lines from the original email headers" className={input}/><span className="mt-1 block text-xs font-normal text-stone-500">Copied header results can be forged; treat them as supporting evidence only.</span></label>
            <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={checkUrls} onChange={e=>setCheckUrls(e.target.checked)} className="mt-1"/><span><b>Check extracted URLs against threat intelligence</b><span className="mt-1 block text-xs font-normal text-stone-500">The backend checks a public phishing feed locally. If a VirusTotal key is configured, URLs not already matched by the feed may be sent to VirusTotal to look up existing reports; the email body and sender are not sent. VirusTotal checks follow its free-tier rate limit.</span></span></label>
        </>}
        {error && <p role="alert" className="text-sm text-rose-600">{error}</p>}
        <button disabled={busy} className="rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60">{busy?"Checking…":tab==="Address Verification"?"Verify email":"Analyze email"}</button>
      </form>
      <Result result={result}/>
    </section>
    {tab === "Address Verification" && <section className={card}>
      <div><h2 className="text-lg font-semibold">Personal Email Check</h2><p className="mt-1 text-sm text-stone-500">Check a Gmail, Outlook, Yahoo, or other personal email domain separately.</p></div>
      <form onSubmit={submitPersonal} className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="block flex-1 text-sm font-medium">Personal Email Address<input required type="email" value={personalEmail} onChange={e=>setPersonalEmail(e.target.value)} placeholder="name@gmail.com" className={input}/></label>
        <button disabled={personalBusy} className="rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60">{personalBusy?"Checking…":"Check personal email"}</button>
      </form>
      {personalError && <p role="alert" className="mt-3 text-sm text-rose-600">{personalError}</p>}
      <Result result={personalResult}/>
      <p className="mt-3 text-xs text-stone-500">This checks the provider domain and address patterns only; it cannot confirm that the individual mailbox exists. Use Content Analysis to check an incoming message for sender and phishing signals.</p>
    </section>}
    <section className={card}>
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">Scan history</h2><p className="text-sm text-stone-500">Audit records from address and content checks</p></div><button onClick={exportHistory} className="rounded-lg border border-stone-300 px-3 py-2 text-sm hover:bg-stone-50 dark:border-stone-600 dark:hover:bg-stone-800">Export CSV</button></div>
      <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search sender, subject, summary, or decision" className={`${input} mb-4`}/>
      <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="text-xs uppercase text-stone-500"><tr>{["Timestamp","Scan Type","Decision","Trust Score","Risk","Confidence","Summary"].map(x=><th key={x} className="px-3 py-2">{x}</th>)}</tr></thead><tbody>{history.map(row=><tr key={row.id} className="border-t border-stone-100 dark:border-stone-800"><td className="whitespace-nowrap px-3 py-3">{new Date(row.ts*1000).toLocaleString()}</td><td className="px-3 py-3">{row.scan_type}</td><td className="px-3 py-3"><DecisionBadge decision={row.decision}/></td><td className="px-3 py-3">{row.reliability}/100</td><td className="px-3 py-3">{row.risk_type}</td><td className="px-3 py-3">{row.confidence}%</td><td className="max-w-xs truncate px-3 py-3" title={row.explanation}>{row.explanation}</td></tr>)}{!history.length&&<tr><td colSpan="7" className="px-3 py-6 text-center text-stone-500">No email scans match this search.</td></tr>}</tbody></table></div>
    </section>
  </div>;
}
