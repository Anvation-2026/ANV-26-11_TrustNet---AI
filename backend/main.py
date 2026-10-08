from typing import Any, Literal
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database as db
import policy_engine
import validator

app = FastAPI(title="TrustNet AI")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
db.init()

REDUNDANT_WINDOW = 60  # seconds
RELIABILITY = {"None": 98, "Redundant Call": 65, "Invalid Parameter": 41,
               "Policy Violation": 35, "Unauthorized Action": 32}

class AgentRequest(BaseModel):
    role: Literal["Admin", "Teacher", "Viewer"]
    tool: str
    action: str
    params: dict[str, Any] = {}

def decide(r: AgentRequest):
    """Run the four checks in order; return (decision, risk_type, rule, explanation)."""
    p = policy_engine.violated(r.role, r.tool, r.params, "Unauthorized Action")  # A
    if p:
        return "Block", "Unauthorized Action", p["id"], p["message"].format(role=r.role)
    err = validator.validate(r.tool, r.params)  # B
    if err:
        return "Block", "Invalid Parameter", "VAL-001", f"Invalid parameters: {err}."
    p = policy_engine.violated(r.role, r.tool, r.params, "Policy Violation")  # D
    if p:
        return "Block", "Policy Violation", p["id"], p["message"].format(role=r.role)
    if db.is_duplicate(r.role, r.tool, r.action, r.params, REDUNDANT_WINDOW):  # C
        return ("Warn", "Redundant Call", "RED-001",
                f"The same request was already executed in the last {REDUNDANT_WINDOW}s, so it was not run again.")
    return "Allow", "None", "-", "Request passed all guardrail checks."

@app.post("/evaluate")
def evaluate(r: AgentRequest):
    decision, risk, rule, why = decide(r)
    score = RELIABILITY[risk]
    db.add_log(r.role, r.tool, r.action, r.params, decision, risk, rule, why, score)
    return {"decision": decision, "risk_type": risk, "rule": rule, "explanation": why, "reliability": score}

@app.get("/stats")
def stats():
    return db.stats()

@app.get("/logs")
def logs():
    return db.recent_logs()

@app.get("/health")
def health():
    return {"status": "ok", "policies": db.policy_count(), "validation": len(validator.SCHEMAS) > 0}
