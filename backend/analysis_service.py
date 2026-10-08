"""Heuristic phishing and social-engineering analysis with URL extraction."""
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse
from email.parser import Parser
from email.policy import default

from email_validator import EmailNotValidError, validate_email

from email_service import FREEMAIL, pattern_checks
from decision_policy import decision_for_score
import threat_intel_service

RECOMMENDATIONS = {
    "Allow": "No configured phishing indicators were detected. Proceed with caution; this does not prove the sender mailbox exists or authenticate the message by itself.",
    "Warn": "Suspicious patterns found. Avoid clicking links or replying; verify the sender through another channel.",
    "Block": "Likely phishing or fraud. Do not click, reply, or act on this email; report it to your security team.",
}
RULES = [
    ("Phishing language", 15, r"\b(dear (customer|user|member|account holder)|click (here|the link below)|security alert|unusual (sign[- ]?in|activity)|suspicious activity|unauthori[sz]ed (access|transaction|login))\b"),
    ("Urgency", 10, r"\b(urgent(ly)?|immediately|asap|act now|right away|final notice|last chance|within (24|48) hours|expires? (today|soon))\b"),
    ("Threatening language", 15, r"\b(account (will be )?(suspended|closed|terminated|locked|deactivated)|legal action|lawsuit|arrest|penalt(y|ies)|permanently (deleted|disabled))\b"),
    ("Credential harvesting", 25, r"\b(verify your (account|identity|password|login)|confirm your (password|credentials|identity|login)|(re-?enter|send|share|provide) (me )?your (password|pin|otp|login|credentials)|one[- ]time (code|password)|update your (billing|payment|account) (info|information|details))\b"),
    ("Social engineering", 15, r"\b(keep this (confidential|between us|secret)|do not (tell|share|discuss)|don'?t tell|are you available|need a (quick )?favou?r|can'?t (talk|take calls|call))\b"),
    ("Payment scam", 20, r"\b(wire transfer|bank (details|account)|payment (is )?overdue|bitcoin|crypto(currency)?|western union|money ?gram|lottery|inheritance|you(?:'ve| have) won|processing fee)\b"),
    ("Gift card scam", 30, r"\b(gift ?cards?|itunes card|google play card|steam card|amazon card|scratch (off|the) (card|code))\b"),
    ("Business Email Compromise", 30, r"\b(new|changed|updated) (bank|account|payment) (details|number|instructions)\b|\bupdate (our|the) (bank|payment) (details|information)\b"),
]
EXECUTIVE = re.compile(r"\b(ceo|cfo|chief (executive|financial) officer|managing director|president|head of finance)\b", re.I)
EXECUTIVE_ASK = re.compile(r"\b(transfer|wire|payment|gift ?cards?|purchase|confidential|urgent|favou?r)\b", re.I)
BRANDS = ("paypal", "microsoft", "apple", "amazon", "google", "netflix", "docusign", "dhl", "fedex")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
HTML_URL_RE = re.compile(r"(?:href|src)\s*=\s*(['\"])(.*?)\1", re.I | re.S)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
RISKY_TLDS = (".zip", ".xyz", ".top", ".click", ".work", ".tk", ".gq")


def _authentication_results(raw_headers: str, sender_domain: str) -> list[dict[str, str]]:
    if not raw_headers.strip():
        return []
    message = Parser(policy=default).parsestr(raw_headers + "\r\n\r\n")
    checks: list[dict[str, str]] = []
    auth_headers = message.get_all("Authentication-Results", [])
    for header in auth_headers:
        text = str(header)
        header_from = re.search(r"\bheader\.from\s*=\s*([^\s;]+)", text, re.I)
        for mechanism, status in re.findall(
            r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            text, re.I,
        ):
            checks.append({"mechanism": mechanism.upper(), "status": status.lower(), "source": "Authentication-Results"})
        if header_from and sender_domain and header_from.group(1).lower() != sender_domain:
            checks.append({"mechanism": "From alignment", "status": "mismatch", "source": "Authentication-Results"})

    if not auth_headers:
        for header in message.get_all("Received-SPF", []):
            match = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", str(header), re.I)
            if match:
                checks.append({"mechanism": "SPF", "status": match.group(1).lower(), "source": "Received-SPF"})
    return checks


def _url_info(raw: str) -> dict[str, Any] | None:
    url = raw.rstrip(".,;:!?")
    try:
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    flags = []
    try:
        ipaddress.ip_address(host)
        flags.append("IP address host")
    except ValueError:
        pass
    if "xn--" in host:
        flags.append("Punycode (possible lookalike)")
    if host in SHORTENERS:
        flags.append("URL shortener")
    if host.endswith(RISKY_TLDS):
        flags.append("Uncommon TLD")
    return {"url": url, "domain": host, "flags": flags}


def analyze(sender_email: str, subject: str, body: str, raw_headers: str = "",
            check_urls: bool = False) -> dict[str, Any]:
    text = f"{subject}\n{body}"
    findings: list[dict[str, Any]] = []
    for category, weight, pattern in RULES:
        matches = [match.group(0) for match in re.finditer(pattern, text, re.I)]
        if matches:
            extra = f" (+{len(matches) - 1} more)" if len(matches) > 1 else ""
            findings.append({"category": category, "weight": weight,
                             "evidence": f"'{matches[0][:60]}'{extra}"})
    if EXECUTIVE.search(text) and EXECUTIVE_ASK.search(text):
        findings.append({"category": "CEO fraud", "weight": 30,
                         "evidence": "Executive reference combined with a payment, secrecy, or urgency request"})

    sender_domain = ""
    sender_valid = True
    try:
        parsed_sender = validate_email(sender_email.strip(), check_deliverability=False)
        sender_domain = parsed_sender.ascii_domain.lower()
        for check in pattern_checks(parsed_sender.local_part, sender_domain):
            if check["status"] == "fail":
                findings.append({"category": "Suspicious sender", "weight": check.get("penalty", 20) // 2,
                                 "evidence": check["detail"]})
    except EmailNotValidError:
        sender_valid = False
        findings.append({"category": "Sender mismatch", "weight": 20, "evidence": "Sender address is not syntactically valid"})
    if sender_valid:
        mentioned_brand = next((brand for brand in BRANDS
                                if re.search(rf"\b{brand}\b", text, re.I) and brand not in sender_domain), None)
        if mentioned_brand:
            findings.append({"category": "Sender mismatch", "weight": 20,
                             "evidence": f"Mentions '{mentioned_brand}' but sender domain is {sender_domain}"})
        if sender_domain in FREEMAIL and EXECUTIVE.search(text):
            findings.append({"category": "Sender mismatch", "weight": 15,
                             "evidence": "Executive or finance request sent from a free-mail address"})

    auth_checks = _authentication_results(raw_headers, sender_domain)
    auth_warning_statuses = {"fail", "softfail", "permerror", "mismatch"}
    for check in auth_checks:
        if check["status"] in auth_warning_statuses:
            weight = 25 if check["mechanism"] == "DMARC" else 20 if check["mechanism"] == "From alignment" else 15
            findings.append({
                "category": "Email authentication failure" if check["mechanism"] != "From alignment" else "Sender mismatch",
                "weight": weight,
                "evidence": f"{check['mechanism']} reported {check['status']} in {check['source']}.",
            })

    urls: list[str] = []
    domains: list[str] = []
    seen: set[str] = set()
    url_details = []
    candidates = URL_RE.findall(text) + [match[1].strip() for match in HTML_URL_RE.findall(text)]
    for raw in candidates:
        if not re.match(r"^(?:https?://|www\.)", raw, re.I):
            continue
        info = _url_info(raw)
        if not info or info["url"] in seen:
            continue
        seen.add(info["url"])
        urls.append(info["url"])
        domains.append(info["domain"])
        url_details.append(info)
        if info["flags"]:
            weight = 15 if len(info["flags"]) > 1 or "IP address host" in info["flags"] else 10
            findings.append({"category": "Suspicious URL", "weight": weight,
                             "evidence": f"{info['domain']}: {', '.join(info['flags'])}"})

    if check_urls and urls:
        threat_check = threat_intel_service.check_urls(urls)
    else:
        threat_check = {
            "provider": "Phishing.Database",
            "status": "not_requested" if urls else "no_urls",
            "checked_at": None,
            "results": [{"url": url, "status": "not_checked", "threat_types": []} for url in urls],
            "note": "URL checks compare extracted URLs locally with a public phishing feed."
            if urls else "No URLs were found to check.",
        }
    matched_urls = [item for item in threat_check["results"] if item["status"] in {"match", "suspicious"}]
    for item in matched_urls:
        matched_domain = (urlparse(item["url"]).hostname or "unknown host").lower()
        suspicious_only = item["status"] == "suspicious"
        source = "VirusTotal" if item.get("virustotal_status") == "match" else "Phishing.Database"
        evidence = (f"{matched_domain} was flagged as suspicious by VirusTotal "
                    f"({item.get('virustotal_suspicious', 0)} suspicious detections)." if suspicious_only else
                    f"{matched_domain} matched {', '.join(item['threat_types'])} on {source}.")
        findings.append({"category": "Threat intelligence match", "weight": 30 if suspicious_only else 70,
                         "evidence": evidence})

    score = max(0, 100 - sum(item["weight"] for item in findings))
    # A reported risk signal must never leave a contradictory safe score. Cap
    # one or more findings at the top of the warning band; accumulated evidence
    # can still reduce the score into the block band below 40.
    if findings:
        score = min(score, 70)
    unresolved_urls = any(item["status"] in {"not_requested", "not_configured", "unavailable", "stale_feed", "not_checked", "not_checked_limit"}
                          for item in threat_check["results"])
    if unresolved_urls:
        score = min(score, 70)
    confidence = min(90, 55 + min(25, len(body.split()) // 4) + (10 if sender_valid else 0))
    decision = decision_for_score(score)
    reasons = [f"{item['category']}: {item['evidence']}" for item in findings] or ["No configured phishing indicators detected."]
    if urls:
        reasons.append(f"Extracted {len(urls)} URL(s) for threat-intelligence checks.")
    if threat_check["status"] == "unavailable":
        reasons.append("The phishing feed could not be refreshed; extracted URLs remain unchecked.")
    elif threat_check["status"] == "stale":
        reasons.append("The phishing feed could not be refreshed; cached feed data is stale and URLs remain unknown.")
    elif threat_check["status"] == "not_requested" and urls:
        reasons.append("Threat-intelligence checks were not requested; URLs remain unknown.")
    elif matched_urls:
        reasons.append(f"The public phishing feed reported {len(matched_urls)} URL match(es).")
    elif threat_check["status"] == "checked":
        reasons.append("The public phishing feed found no known URL match; this does not prove URLs are safe.")
    if raw_headers.strip():
        reasons.append("Authentication header results are user-supplied and were not independently verified.")
    return {
        "scan_type": "Email Content", "trust_score": score, "confidence": confidence,
        "risk": {"Allow": "Low", "Warn": "Medium", "Block": "High"}[decision],
        "decision": decision, "decision_code": decision.upper(), "reasons": reasons, "recommendation": RECOMMENDATIONS[decision],
        "findings": [item["category"] for item in findings], "finding_details": findings,
        "auth_checks": auth_checks,
        "auth_header_notice": "Authentication results are copied from the supplied headers and may be forged; use them as supporting evidence only." if raw_headers.strip() else "",
        "urls": urls, "domains": domains, "url_details": url_details,
        "threat_intelligence": threat_check["results"],
        "threat_intelligence_check": {key: value for key, value in threat_check.items() if key != "results"},
    }


analyze_email = analyze
