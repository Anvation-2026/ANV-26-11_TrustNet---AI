# TrustNet-AI – Enterprise AI Trust & Security Platform

TrustNet-AI checks each agent request (role, tool, action, parameters) **before execution** and returns
a decision (Allow / Warn / Block), risk type, violated rule, explanation and a 0–100 reliability score.

Checks, in order: **A** unauthorized action (role rules in `policies.json`) → **B** invalid/hallucinated
parameters (Pydantic, unknown fields rejected) → **D** policy violation (`policies.json`) →
**C** redundant call (identical allowed request in the last 60 s → Warn).

## Folder structure
```
backend/   main.py (API + decision engine), validator.py (Pydantic), policy_engine.py,
           email_service.py, dns_service.py, analysis_service.py,
           database.py (SQLite: policies + logs), policies.json
frontend/  src/pages (Home, Simulator, Dashboard), src/components, src/services
```

## One-time backend setup

Create the Python environment and install backend dependencies once:

```
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Start the app

From `frontend/`, run `npm run dev`. Vite automatically starts the FastAPI backend on port 8000,
loads `backend/.env` when present, and stops the backend when the frontend dev server closes. If the
backend is already running on port 8000, Vite reuses it. Backend output appears in the same terminal.

### Personal Email Check

The Personal Email Check performs syntax, DNS, disposable-provider, and address-pattern checks without sending email. DNS can assess the provider domain, but it cannot confirm whether an individual mailbox such as `name@gmail.com` exists. Use Content Analysis to assess an incoming message's sender, subject, body, and URLs.

Content Analysis accepts optional original `Authentication-Results` and `Received-SPF` headers. These are treated as supporting evidence because text pasted into the form cannot be independently authenticated. Email bodies are analyzed in memory and are not stored in audit records; audit history keeps the sender, subject, decision, score, and summary.

For deployments outside local development, set `CORS_ALLOW_ORIGINS` to a comma-separated list of trusted frontend origins. The API currently has no user authentication and should not be exposed directly to an untrusted network.

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

## Live URL Threat Checks

Email Content Analysis checks extracted URLs against the public
[Phishing.Database feed](https://github.com/Phishing-Database/Phishing.Database) when the user enables the
checkbox. The feed needs no key; it is cached for an hour and compared locally. Optionally set
`VIRUSTOTAL_API_KEY` in `backend/.env` to query existing VirusTotal URL reports. VirusTotal receives the
extracted URLs (not the sender, subject, or body). The integration only retrieves existing reports; it does
not submit or rescan URLs. VirusTotal's free Community API is limited to 4 requests per minute and is not
permitted for commercial products or services. A match is threat evidence, but a no-match does not prove a
URL safe. If the feed or VirusTotal is unavailable, those results are shown as unknown. Copy
`backend/.env.example` to `backend/.env` to configure either optional setting, then start Uvicorn from
`backend/` with `uvicorn main:app --reload --env-file .env`. Keep `.env` untracked.
## Repeatable Adaptive Guardrail Demo

In Simulator, click **Reset adaptive demo**, load **Adaptive Policy Demo**, and run the invalid request three
times. Then change the path parameter to `/documents/company_policy.pdf` and run it. The fourth request
should show WARN (ADP-001) with the three blocked requests as evidence. The demo trace is isolated to the
current browser session and reset does not delete audit history.

Run backend checks from `backend/` with `python -m unittest discover -s tests`.

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
