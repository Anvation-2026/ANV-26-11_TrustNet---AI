import json, os, sqlite3, time

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "pygenic.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies(
  id TEXT PRIMARY KEY, tool TEXT, category TEXT,
  allowed_roles TEXT, max_amount REAL, message TEXT);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, role TEXT, tool TEXT,
  action TEXT, params TEXT, decision TEXT, risk_type TEXT, rule TEXT,
  explanation TEXT, reliability INTEGER);
"""

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    """Create tables and reload policies.json into the policies table."""
    with conn() as c:
        c.executescript(SCHEMA)
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

def add_log(role, tool, action, params, decision, risk, rule, explanation, reliability):
    with conn() as c:
        c.execute(
            "INSERT INTO logs (ts,role,tool,action,params,decision,risk_type,rule,explanation,reliability) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (time.time(), role, tool, action, canon(params), decision, risk, rule, explanation, reliability))

def recent_logs(n=20):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (n,))]

DECISIONS = ["Allow", "Warn", "Block"]
RISKS = ["Unauthorized Action", "Invalid Parameter", "Policy Violation", "Redundant Call"]

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
