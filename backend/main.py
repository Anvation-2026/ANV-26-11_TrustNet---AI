import os
from typing import Any, Literal
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi import Query

import database as db
import policy_engine
import validator
import email_service
import analysis_service
import dns_service
import behavior_engine
from decision_policy import decision_for_score

app = FastAPI(title="TrustNet-AI | AI Trust & Security")
cors_origins = [origin.strip() for origin in os.getenv(
    "CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
db.init()

REDUNDANT_WINDOW = 60  # seconds
RELIABILITY = {"None": 98, "Redundant Call": 65, "Invalid Parameter": 39,
               "Policy Violation": 35, "Unauthorized Action": 32}

class AgentRequest(BaseModel):
    role: Literal["Admin", "Teacher", "Viewer"]
    tool: str
    action: str
    params: dict[str, Any] = {}
    trace_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,64}$")

class EmailAddressRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)

class EmailContentRequest(BaseModel):
    sender_email: str = Field(min_length=3, max_length=320)
    subject: str = Field(default="", max_length=998)
    body: str = Field(min_length=1, max_length=100_000)
    raw_headers: str = Field(default="", max_length=50_000)
    check_urls: bool = False

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
    behavior = behavior_engine.assess(r.role, r.tool, r.trace_id)
    if decision == "Allow" and behavior["adaptive_policy"]["applied"]:
        decision, risk, rule = "Warn", "Adaptive Behavior", "ADP-001"
        why = behavior["adaptive_policy"]["reason"]
    score = RELIABILITY.get(risk, 70)
    if risk == "Adaptive Behavior":
        score = max(50, behavior["behavioral_score"])
    # A policy/validation Block remains a hard stop regardless of score.
    if decision != "Block":
        decision = decision_for_score(score)
    db.add_log(r.role, r.tool, r.action, r.params, decision, risk, rule, why, score, r.trace_id)
    risk_level = "High" if decision == "Block" else "Medium" if decision == "Warn" else "Low"
    recommendation = {
        "Allow": "The request passed current policy and validation checks.",
        "Warn": "Review the warning before retrying or taking a related action.",
        "Block": "Do not perform this action until the policy or validation issue is resolved.",
    }[decision]
    return {
        # Keep existing response fields for current clients.
        "decision": decision, "risk_type": risk, "rule": rule,
        "explanation": why, "reliability": score,
        # Shared trust assessment fields used by Email Trust.
        "decision_code": decision.upper(), "trust_score": score, "confidence": 100,
        "risk": risk_level, "reasons": [why], "recommendation": recommendation,
        **behavior,
    }

@app.get("/stats")
def stats():
    return db.stats()

@app.get("/logs")
def logs():
    return db.recent_logs()

@app.post("/email/verify")
def verify_email(r: EmailAddressRequest):
    result = email_service.verify_address(r.email)
    summary = "; ".join(result["reasons"])
    db.add_email_log("Address Verification", result["decision"], result["risk"],
                     result["trust_score"], result["confidence"], summary, {"email": r.email})
    return result

@app.post("/email/verify-personal")
def verify_personal_email(r: EmailAddressRequest):
    result = email_service.verify_address(r.email)
    result["scan_type"] = "Personal Email Check"
    summary = "; ".join(result["reasons"])
    db.add_email_log("Personal Email Check", result["decision"], result["risk"],
                     result["trust_score"], result["confidence"], summary, {"email": r.email})
    return result

@app.post("/email/analyze")
def analyze_email(r: EmailContentRequest):
    result = analysis_service.analyze(r.sender_email, r.subject, r.body, r.raw_headers, r.check_urls)
    summary = "; ".join(dict.fromkeys(result["reasons"]))[:1000]
    db.add_email_log("Content Analysis", result["decision"], result["risk"],
                     result["trust_score"], result["confidence"], summary,
                     {"sender_email": r.sender_email, "subject": r.subject, "findings": result["findings"],
                      "threat_intelligence_status": result["threat_intelligence_check"]["status"]})
    return result

@app.get("/email/history")
def email_history(q: str = Query(default="", max_length=200)):
    return db.email_history(query=q)

@app.get("/email/dns-check")
def email_dns_check():
    """Report which DNS resolver paths respond from the backend host."""
    return {"fallback_enabled": dns_service.fallback_enabled(), "routes": dns_service.diagnose()}

@app.get("/email/stats")
def email_stats():
    return db.email_stats()

@app.get("/health")
def health():
    return {"status": "ok", "policies": db.policy_count(), "validation": len(validator.SCHEMAS) > 0}
