import json, os, sqlite3, time
from contextlib import contextmanager
from typing import Iterator

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.getenv("PYGENIC_DB_PATH", os.path.join(HERE, "pygenic.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies(
  id TEXT PRIMARY KEY, tool TEXT, category TEXT,
  allowed_roles TEXT, max_amount REAL, message TEXT);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, role TEXT, tool TEXT,
  action TEXT, params TEXT, decision TEXT, risk_type TEXT, rule TEXT,
  explanation TEXT, reliability INTEGER);
"""

@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def init():
    """Create tables and reload policies.json into the policies table."""
    with conn() as c:
        c.executescript(SCHEMA)
        # Additive migration: preserve existing guardrail records and table structure.
        columns = {row[1] for row in c.execute("PRAGMA table_info(logs)")}
        if "scan_type" not in columns:
            c.execute("ALTER TABLE logs ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'Guardrail'")
        if "confidence" not in columns:
            c.execute("ALTER TABLE logs ADD COLUMN confidence INTEGER NOT NULL DEFAULT 100")
        if "trace_id" not in columns:
            c.execute("ALTER TABLE logs ADD COLUMN trace_id TEXT")
        c.execute("DELETE FROM policies")
        with open(os.path.join(HERE, "policies.json")) as f:
            for p in json.load(f):
                c.execute("INSERT INTO policies VALUES (?,?,?,?,?,?)", (
                    p["id"], p["tool"], p["category"],
                    json.dumps(p.get("allowed_roles")), p.get("max_amount"), p["message"]))

def get_policies(tool, category):
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM policies WHERE tool=? AND category=?", (tool, category))]

def canon(params):
    return json.dumps(params, sort_keys=True)

def is_duplicate(role, tool, action, params, window):
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM logs WHERE role=? AND tool=? AND action=? AND params=? "
            "AND decision='Allow' AND ts>? LIMIT 1",
            (role, tool, action, canon(params), time.time() - window)).fetchone()
        return row is not None

def behavior_state(role, tool, window, trace_id=None):
    """Aggregate recent simulated decisions for one role and tool."""
    with conn() as c:
        sql = "SELECT decision, COUNT(*) n FROM logs WHERE scan_type='Guardrail' AND role=? AND tool=? AND ts>?"
        values = [role, tool, time.time() - window]
        if trace_id:
            sql += " AND trace_id=?"
            values.append(trace_id)
        sql += " GROUP BY decision"
        rows = c.execute(sql, values).fetchall()
    counts = {row["decision"]: row["n"] for row in rows}
    return {
        "window_seconds": window,
        "total": sum(counts.values()),
        "allowed": counts.get("Allow", 0),
        "warned": counts.get("Warn", 0),
        "blocked": counts.get("Block", 0),
    }

def add_log(role, tool, action, params, decision, risk, rule, explanation, reliability, trace_id=None):
    with conn() as c:
        c.execute(
            "INSERT INTO logs (ts,role,tool,action,params,decision,risk_type,rule,explanation,reliability,trace_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), role, tool, action, canon(params), decision, risk, rule, explanation, reliability, trace_id))

def recent_logs(n=20):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (n,))]

def add_email_log(scan_type, decision, risk, score, confidence, summary, details):
    with conn() as c:
        c.execute(
            "INSERT INTO logs (ts,role,tool,action,params,decision,risk_type,rule,explanation,reliability,scan_type,confidence) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), "System", "Email Trust", scan_type, canon(details), decision, risk,
             "EMAIL-TRUST", summary, score, scan_type, confidence))

def email_history(n=100, query=""):
    with conn() as c:
        like = f"%{query}%"
        return [dict(r) for r in c.execute(
            "SELECT * FROM logs WHERE scan_type IN ('Address Verification','Personal Email Check','Content Analysis') "
            "AND (params LIKE ? OR explanation LIKE ? OR decision LIKE ?) ORDER BY id DESC LIMIT ?",
            (like, like, like, n))]

def email_stats():
    with conn() as c:
        row = c.execute(
            "SELECT COUNT(*) scanned, "
            "COALESCE(SUM(CASE WHEN decision='Allow' THEN 1 ELSE 0 END),0) safe, "
            "COALESCE(SUM(CASE WHEN decision='Warn' THEN 1 ELSE 0 END),0) suspicious, "
            "COALESCE(SUM(CASE WHEN decision='Block' THEN 1 ELSE 0 END),0) high_risk "
            "FROM logs WHERE scan_type IN ('Address Verification','Personal Email Check','Content Analysis')"
        ).fetchone()
        return dict(row)

DECISIONS = ["Allow", "Warn", "Block"]
RISKS = ["Unauthorized Action", "Invalid Parameter", "Policy Violation", "Redundant Call", "Adaptive Behavior", "Low", "Medium", "High"]

def stats():
    with conn() as c:
        by = {r["decision"]: r["n"] for r in c.execute("SELECT decision, COUNT(*) n FROM logs GROUP BY decision")}
        risk = {r["risk_type"]: r["n"] for r in c.execute("SELECT risk_type, COUNT(*) n FROM logs GROUP BY risk_type")}
        avg = c.execute("SELECT AVG(reliability) a FROM logs").fetchone()["a"]
    decisions = [{"name": d, "value": by.get(d, 0)} for d in DECISIONS]  # always all three, zeros included
    return {"total": sum(d["value"] for d in decisions), "allowed": by.get("Allow", 0),
            "warned": by.get("Warn", 0), "blocked": by.get("Block", 0),
            "reliability": round(avg) if avg is not None else 100,
            "decisions": decisions,
            "risk_types": [{"name": r, "value": risk.get(r, 0)} for r in RISKS]}

def policy_count():
    with conn() as c:
        return c.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
