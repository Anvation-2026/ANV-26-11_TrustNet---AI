# TrustNet AI – AI Agent Reliability & Guardrail Engine

Hackathon MVP. An agent request (role, tool, action, parameters) is checked **before execution** and gets
a decision (Allow / Warn / Block), risk type, violated rule, explanation and a 0–100 reliability score.

Checks, in order: **A** unauthorized action (role rules in `policies.json`) → **B** invalid/hallucinated
parameters (Pydantic, unknown fields rejected) → **D** policy violation (`policies.json`) →
**C** redundant call (identical allowed request in the last 60 s → Warn).

## Folder structure
```
backend/   main.py (API + decision engine), validator.py (Pydantic), policy_engine.py,
           database.py (SQLite: policies + logs), policies.json
frontend/  src/pages (Home, Simulator, Dashboard), src/components, src/services
```

## Run the backend (port 8000)
```
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Run the frontend (port 5173)
```
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. To use another API address, set `VITE_API_URL`.

## Quick Demo Scenarios and System Status
- **Quick Demo Scenarios** (top of the Simulator page): Safe Email, Unauthorized Delete User, Invalid Email,
  Duplicate Payment, Invalid Payment Amount, Invalid File Path. A click fills the manual simulator
  (role, tool, action, parameters) but does not run it; click **Run Guardrail Check**. Duplicate Payment: run it twice within 60 s.
- **System Status** (top-right): shows Guardrail Engine Online/Offline, backend connection, number of policies loaded
  and validation readiness, from the backend `GET /health` endpoint (refreshes every 10 s).
- **Dashboard**: colored cards (blue total, green allowed, red blocked, yellow warnings), average reliability score,
  risk-type pie chart and request history; refreshes every 5 s.

## AI Agent Output (simulate a real agent)
The top section of the Simulator page accepts a JSON tool call produced by an AI agent (Aurelia Learn,
ChatGPT, Claude, Gemini, ...). It uses the same guardrail engine and logs as the manual form.

1. Open **Simulator** and paste the agent's JSON into **AI Agent Output**.
2. Click **Validate AI Output**.
3. The manual form below fills in automatically, and the decision, risk type, rule, explanation and
   reliability score appear next to the text area. The request is saved to the logs.
4. Open **Dashboard**; it refreshes every 5 seconds, so the new request shows up on its own.

Format (`parameters` is also accepted as `params`; role and action are case-insensitive; a ```json code fence is fine):
```
{
  "role": "Admin",
  "tool": "send_email",
  "action": "execute",
  "parameters": { "to": "teacher@school.edu", "subject": "Homework Reminder", "body": "Please submit your assignment before Friday." }
}
```
Try these: the email above (Allow); `{"role": "Viewer", "tool": "delete_user", "action": "execute",
"parameters": {"user_id": 1024, "reason": "Inactive account"}}` (Block, POL-001); `{"role": "Admin",
"tool": "process_payment", "action": "execute", "parameters": {"recipient": "ABC Suppliers", "amount": 50000,
"currency": "INR"}}` (Allow, then Warn RED-001 if pasted again within 60 s).

Malformed JSON (a missing comma or quote), a missing role/tool/action, or an unknown role shows a friendly
error instead of calling the engine. An unknown tool or bad parameters are sent to the engine and blocked (VAL-001).
The manual simulator below is unchanged for custom inputs.

## Tool schemas (all fields required, unknown fields rejected)
| Tool | Fields |
|---|---|
| read_file | path |
| delete_user | user_id (int > 0), reason |
| export_data | dataset, format (csv / json / xlsx) |
| send_email | to (valid email), subject, body |
| process_payment | recipient, amount (> 0), currency (3 capital letters, e.g. INR) |
| schedule_event | title, date (YYYY-MM-DD), time (HH:MM), attendees (list of valid emails, at least one) |

## Demo scenarios (Simulator: click the tool's example button, or pick a tool to load its payload)
1. **read_file** (Viewer, example as loaded) → Allow
2. **delete_user** (Viewer, example as loaded) → Block, POL-001 (unauthorized)
3. **export_data** (Teacher, example as loaded) → Block, POL-002 (policy: Admin only)
4. **send_email** (Teacher): change `to` to `manager@company` → Block, VAL-001 (invalid email)
5. **process_payment** (Admin, example as loaded): submit twice within 60 s → Allow, then Warn RED-001
6. **schedule_event** (Teacher, example as loaded) → Allow

More validation checks: missing `path`, `amount: -5000`, `format: "pdf"`, `date: "2026-02-30"` → Block, VAL-001.
Admin `amount: 500000` → Block, POL-004 (payment cap 100000).
