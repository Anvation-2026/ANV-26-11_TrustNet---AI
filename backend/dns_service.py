"""DNS checks used for technical email domain signals."""
from dataclasses import dataclass
import json
import os
import re
import time
from typing import Any
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import dns.resolver

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "temp-mail.org", "trashmail.com",
    "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc", "fakeinbox.com",
}
TIMEOUT = 4.0
PUBLIC_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
TYPE_CODES = {"MX": 15, "TXT": 16}


@dataclass(frozen=True)
class DnsResult:
    status: str  # found, missing, error
    records: list[str]
    detail: str = ""


def _via_dnspython(name: str, record_type: str, nameservers: list[str] | None = None, tcp: bool = False) -> DnsResult:
    try:
        resolver = dns.resolver.Resolver(configure=nameservers is None)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.timeout = resolver.lifetime = TIMEOUT
        answers = resolver.resolve(name, record_type, tcp=tcp)
        if record_type == "TXT":
            records = ["".join(part.decode("utf-8", "ignore") for part in answer.strings) for answer in answers]
        else:
            records = [answer.to_text() for answer in answers]
        return DnsResult("found" if records else "missing", records)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return DnsResult("missing", [])
    except Exception as exc:
        return DnsResult("error", [], type(exc).__name__)


def _doh(endpoint: str, name: str, record_type: str) -> DnsResult:
    try:
        url = f"{endpoint}?name={urllib.parse.quote(name)}&type={record_type}"
        request = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.load(response)
        status = data.get("Status")
        if status == 3:
            return DnsResult("missing", [])
        if status != 0:
            return DnsResult("error", [], f"RCODE{status}")
        answers = [answer["data"] for answer in data.get("Answer", [])
                   if answer.get("type") == TYPE_CODES[record_type]]
        if record_type == "TXT":
            answers = [re.sub(r'"\s*"', "", answer).strip('"') for answer in answers]
        return DnsResult("found", answers) if answers else DnsResult("missing", [])
    except Exception as exc:
        return DnsResult("error", [], type(exc).__name__)


METHODS = {
    "system": lambda name, kind: _via_dnspython(name, kind),
    "public-udp": lambda name, kind: _via_dnspython(name, kind, PUBLIC_NAMESERVERS),
    "public-tcp": lambda name, kind: _via_dnspython(name, kind, PUBLIC_NAMESERVERS, tcp=True),
    "doh-google": lambda name, kind: _doh("https://dns.google/resolve", name, kind),
    "doh-cloudflare": lambda name, kind: _doh("https://cloudflare-dns.com/dns-query", name, kind),
}


def fallback_enabled() -> bool:
    return os.getenv("DNS_FALLBACK", "on").lower() != "off"


def _query(name: str, record_type: str) -> DnsResult:
    routes = METHODS if fallback_enabled() else {"system": METHODS["system"]}
    errors: dict[str, str] = {}
    pool = ThreadPoolExecutor(max_workers=len(routes))
    pending = {pool.submit(route, name, record_type): route_name for route_name, route in routes.items()}
    try:
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                route_name = pending.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    errors[route_name] = type(exc).__name__
                    continue
                if result.status != "error":
                    return result
                errors[route_name] = result.detail
        detail = errors.get("system") or next(iter(errors.values()), "NoRoute")
        if len(errors) > 1:
            detail += "; fallback routes also failed"
        return DnsResult("error", [], detail)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def lookup_result(domain: str, record_type: str) -> DnsResult:
    return _query(domain, record_type)


def lookup_mx(domain: str) -> DnsResult:
    return _query(domain, "MX")


def lookup_spf(domain: str) -> DnsResult:
    result = _query(domain, "TXT")
    if result.status != "found":
        return result
    records = [record for record in result.records if record.lower().startswith("v=spf1")]
    return DnsResult("found" if records else "missing", records)


def lookup_dmarc(domain: str) -> DnsResult:
    result = _query(f"_dmarc.{domain}", "TXT")
    if result.status != "found":
        return result
    records = [record for record in result.records if record.lower().startswith("v=dmarc1")]
    return DnsResult("found" if records else "missing", records)


def lookup(domain: str, record_type: str) -> list[str]:
    return _query(domain, record_type).records


def diagnose(name: str = "gmail.com") -> list[dict[str, Any]]:
    """Show which DNS paths are responding for one domain lookup."""
    def run(item):
        route_name, route = item
        started = time.perf_counter()
        result = route(name, "MX")
        return {"route": route_name, "status": result.status,
                "ms": round((time.perf_counter() - started) * 1000), "detail": result.detail}

    with ThreadPoolExecutor(max_workers=len(METHODS)) as pool:
        return list(pool.map(run, METHODS.items()))


def technical_checks(domain: str) -> dict[str, Any]:
    mx, spf, dmarc = lookup_mx(domain), lookup_spf(domain), lookup_dmarc(domain)
    return {
        "mx": {"passed": mx.status == "found", "records": mx.records, "status": mx.status},
        "spf": {"passed": spf.status == "found", "records": spf.records, "status": spf.status},
        "dmarc": {"passed": dmarc.status == "found", "records": dmarc.records, "status": dmarc.status},
        "disposable": domain.lower() in DISPOSABLE_DOMAINS,
    }


class ReputationAdapter:
    """Extension point for a future reputation provider; no external calls today."""
    name = "unconfigured"

    def check(self, domain: str) -> dict[str, Any]:
        return {"provider": self.name, "available": False, "domain": domain, "signal": None}
