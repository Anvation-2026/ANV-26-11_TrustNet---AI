const email = { to: "manager@company.com", subject: "Monthly Sales Report", body: "Please find the report attached." };
const pay = { recipient: "ABC Suppliers", amount: 50000, currency: "INR" };

export const SCENARIOS = [
  { icon: "✅", label: "Safe Email", tone: "good", role: "Teacher", tool: "send_email", action: "Execute",
    params: email, hint: "Expected: Allow." },
  { icon: "❌", label: "Unauthorized Delete User", tone: "bad", role: "Viewer", tool: "delete_user", action: "Execute",
    params: { user_id: 1024, reason: "Inactive account" }, hint: "Expected: Block (POL-001)." },
  { icon: "❌", label: "Invalid Email", tone: "bad", role: "Teacher", tool: "send_email", action: "Execute",
    params: { ...email, to: "manager@company" }, hint: "Expected: Block (VAL-001)." },
  { icon: "⚠", label: "Duplicate Payment", tone: "warn", role: "Admin", tool: "process_payment", action: "Execute",
    params: pay, hint: "Run it twice within 60 seconds: Allow, then Warn (RED-001)." },
  { icon: "❌", label: "Invalid Payment Amount", tone: "bad", role: "Admin", tool: "process_payment", action: "Execute",
    params: { ...pay, amount: -5000 }, hint: "Expected: Block (VAL-001)." },
  { icon: "❌", label: "Invalid File Path", tone: "bad", role: "Viewer", tool: "read_file", action: "Read",
    params: { path: "" }, hint: "Expected: Block (VAL-001)." },
  { icon: "ℹ️", label: "Adaptive Policy Demo", tone: "warn", role: "Viewer", tool: "read_file", action: "Read",
    params: { path: "" }, hint: "Run this invalid request three times, then retry with path /documents/company_policy.pdf to see ADP-001 warn using recent trace evidence." },
];
