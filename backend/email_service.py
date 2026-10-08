"""Technical address trust checks; these checks never establish mailbox ownership."""
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from email_validator import EmailNotValidError, validate_email

import dns_service
from decision_policy import decision_for_score

DISPOSABLE = dns_service.DISPOSABLE_DOMAINS
FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com",
    "outlook.in", "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "zoho.com", "yandex.com", "rediffmail.com",
}
BRAND_DOMAINS = (
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com", "netflix.com",
    "facebook.com", "instagram.com", "linkedin.com", "whatsapp.com", "docusign.com", "dhl.com", "fedex.com",
)
POPULAR = FREEMAIL | set(BRAND_DOMAINS)
LEGIT_SIMILAR = {"mail.com", "email.com", "gmx.net", "pm.me"}
BRANDS = tuple(domain.split(".")[0] for domain in BRAND_DOMAINS)
OFFICIAL_WORDS = {
    "support", "security", "billing", "helpdesk", "admin", "administrator", "payroll", "accounts",
    "accounting", "refund", "verify", "verification", "alert", "official", "service", "customercare",
    "ceo", "cfo", "hr", "notification", "notifications", "compliance", "fraud", "recovery",
}
WEIGHTS = {"Syntax": 20, "MX records": 30, "SPF record": 15, "DMARC record": 15, "Not disposable": 20}
RISK = {"Allow": "Low", "Warn": "Medium", "Block": "High"}
ORDER = {"Allow": 0, "Warn": 1, "Block": 2}
RECOMMENDATIONS = {
    "Allow": "No configured technical red flags were found. Proceed with caution; this does not verify an individual mailbox or guarantee that future messages are safe.",
    "Warn": "Some trust signals are missing, unavailable, or suspicious. Confirm through a second channel before sensitive actions.",
    "Block": "Technical signals indicate this address is unreliable. Do not send sensitive data to it.",
}
NOTICE = "Technical trust signals only. This cannot confirm whether an individual mailbox exists or who controls it."
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e"})


def _normalize(text: str) -> str:
    return text.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _distance(a: str, b: str) -> int:
    """Edit distance with adjacent transposition counted as one edit."""
    rows = [list(range(len(b) + 1))]
    for i, ca in enumerate(a, 1):
        row = [i]
        for j, cb in enumerate(b, 1):
            row.append(min(rows[-1][j] + 1, row[-1] + 1, rows[-1][j - 1] + (ca != cb)))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def _official_domain(domain: str, brand: str) -> bool:
    parts = domain.split(".")
    names = {parts[-2]} if len(parts) >= 2 else set()
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac"}:
        names.add(parts[-3])
    return brand in names


def _lookalike(domain: str) -> tuple[str, bool] | None:
    if domain in POPULAR or domain in LEGIT_SIMILAR:
        return None
    for target in POPULAR:
        if _normalize(domain) == target:
            return target, True
        if _distance(domain, target) <= (1 if len(target) < 12 else 2):
            return target, False
    return None


def _check(name: str, status: str, detail: str, penalty: int = 0) -> dict[str, Any]:
    result = {"name": name, "status": status, "detail": detail}
    if penalty:
        result["penalty"] = penalty
    return result


def _pattern_checks(local: str, domain: str) -> list[dict[str, Any]]:
    checks = []
    lookalike = _lookalike(domain)
    domain_brand = next((brand for brand in BRANDS
                         if brand in re.split(r"[^a-z0-9]+", domain.rsplit(".", 1)[0])
                         and not _official_domain(domain, brand)), None)
    if lookalike:
        checks.append(_check("Lookalike domain", "fail", f"Domain closely resembles '{lookalike[0]}'.", 60 if lookalike[1] else 45))
    elif domain_brand:
        checks.append(_check("Lookalike domain", "fail", f"Domain uses the '{domain_brand}' brand name but is not an official domain.", 60))
    elif "xn--" in domain:
        checks.append(_check("Lookalike domain", "fail", "Domain uses punycode characters that can imitate other domains.", 35))
    else:
        checks.append(_check("Lookalike domain", "pass", "Domain does not imitate a known provider or brand."))

    lower_local = local.lower()
    switches = len(re.findall(r"(?<=\d)[a-z]|(?<=[a-z])\d", lower_local))
    username_flags = []
    if len(lower_local) >= 8 and (re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", lower_local) or switches >= 5):
        username_flags.append("random-looking username")
    digits = sum(char.isdigit() for char in lower_local)
    if digits >= 8 or (digits >= 6 and digits / max(1, len(lower_local)) >= 0.5):
        username_flags.append("mostly digits")
    tokens = [token for token in re.split(r"[._\-+0-9]+", lower_local) if token]
    if domain in FREEMAIL and any(token in OFFICIAL_WORDS for token in tokens):
        username_flags.append("official-sounding name on a free-mail address")
    if any(brand in tokens and not _official_domain(domain, brand) for brand in BRANDS):
        username_flags.append("uses a brand name in the username")
    if username_flags:
        checks.append(_check("Username pattern", "fail", "Username shows: " + "; ".join(username_flags) + ".", min(70, 30 * len(username_flags))))
    else:
        checks.append(_check("Username pattern", "pass", "No configured suspicious username patterns found."))
    return checks


def pattern_checks(local: str, domain: str) -> list[dict[str, Any]]:
    """Return best-effort address pattern checks for use by message analysis."""
    try:
        return _pattern_checks(local, domain)
    except Exception:
        return [_check("Username pattern", "unknown", "Pattern analysis unavailable.")]


def _dns_check(name: str, result: dns_service.DnsResult, found: str, missing: str) -> dict[str, Any]:
    if result.status == "found":
        return _check(name, "pass", found)
    if result.status == "missing":
        return _check(name, "fail", missing)
    return _check(name, "unknown", f"{name} lookup unavailable ({result.detail or 'DNS resolver error'}).")


def verify_email(address: str) -> dict[str, Any]:
    address = address.strip()
    try:
        parsed = validate_email(address, check_deliverability=False)
    except EmailNotValidError as exc:
        check = _check("Syntax", "fail", str(exc))
        return _result(address, None, [check], [])

    domain = parsed.ascii_domain.lower()
    # Parallel DNS lookups keep a slow resolver from multiplying the wait time.
    with ThreadPoolExecutor(max_workers=3) as pool:
        mx, spf, dmarc = pool.map(
            lambda lookup: lookup(domain),
            (dns_service.lookup_mx, dns_service.lookup_spf, dns_service.lookup_dmarc),
        )
    disposable = any(domain == item or domain.endswith("." + item) for item in DISPOSABLE)
    checks = [
        _check("Syntax", "pass", "Address format is valid."),
        _dns_check("MX records", mx, f"Mail servers found ({len(mx.records)}).", "No MX records: the domain cannot receive mail."),
        _dns_check("SPF record", spf, "SPF policy published.", "No SPF policy published."),
        _dns_check("DMARC record", dmarc, "DMARC policy published.", "No DMARC policy published."),
        _check("Not disposable", "fail" if disposable else "pass",
               "Domain is a known disposable-email provider." if disposable else "Not on the disposable-provider list."),
    ] + _pattern_checks(parsed.local_part, domain)
    return _result(address, domain, checks, [])


def _result(address: str, domain: str | None, checks: list[dict[str, Any]], reputation: list) -> dict[str, Any]:
    statuses = {check["name"]: check["status"] for check in checks}
    known_weight = sum(WEIGHTS.get(name, 0) for name, status in statuses.items() if status != "unknown")
    earned = sum(WEIGHTS.get(name, 0) for name, status in statuses.items() if status == "pass")
    score = round(100 * earned / known_weight) if known_weight else 0
    penalty = sum(check.get("penalty", 0) for check in checks if check["status"] == "fail")
    score = max(0, score - penalty)
    if statuses.get("MX records") == "fail":
        score = min(score, 25)
    if statuses.get("Not disposable") == "fail":
        score = min(score, 35)
    if any(signal.get("verdict") == "malicious" for signal in reputation):
        score = min(score, 10)
    freemail = domain in FREEMAIL if domain else False
    confidence = 95 if statuses.get("Syntax") == "fail" else round(known_weight * 0.9)
    if freemail:
        confidence = min(confidence, 60)  # domain records cannot establish trust in a particular mailbox
        score = min(score, 70)
    low_confidence = confidence < 50
    if low_confidence:
        score = min(score, 60)
    failed = [name for name, status in statuses.items() if status == "fail"]
    unavailable = [name for name, status in statuses.items() if status == "unknown"]
    reasons = [check["detail"] for check in checks if check["status"] != "pass"]
    if not reasons:
        reasons = ["All available technical checks passed."]
    if freemail:
        reasons.append("Free-mail provider: domain signals describe the provider, not this specific mailbox.")
    if low_confidence:
        reasons.append("Too few DNS signals were available for a confident assessment.")
    penalty_present = penalty > 0 or bool(failed)
    # Incomplete, failed, or freemail domain-only signals cannot reach the safe band.
    if low_confidence or penalty_present or freemail:
        score = min(score, 70)
    decision = decision_for_score(score)
    return {
        "scan_type": "Email Verification", "decision": decision, "decision_code": decision.upper(), "trust_score": score,
        "confidence": confidence, "risk": RISK[decision], "reasons": reasons,
        "recommendation": RECOMMENDATIONS[decision], "target": address, "domain": domain,
        "checks": checks, "notice": NOTICE, "personal_address": freemail,
        "checks_passed": [name for name, status in statuses.items() if status == "pass"],
        "checks_failed": failed, "checks_unavailable": unavailable,
        # Preserve the original UI/API response fields for existing clients.
        "signals": {
            "syntax": {"passed": statuses.get("Syntax") == "pass"},
            "mx": {"passed": statuses.get("MX records") == "pass"},
            "spf": {"passed": statuses.get("SPF record") == "pass"},
            "dmarc": {"passed": statuses.get("DMARC record") == "pass"},
            "disposable": domain in DISPOSABLE if domain else False,
            "reputation": {"provider": "unconfigured", "available": False, "signals": reputation},
        },
    }


def verify_address(address: str) -> dict[str, Any]:
    """Backward-compatible function name used by the existing FastAPI route."""
    return verify_email(address)
